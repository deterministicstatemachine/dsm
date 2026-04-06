import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import com.google.protobuf.gradle.proto
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.application")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")  // Required for Kotlin 2.0.x Compose
    id("jacoco")
    id("io.gitlab.arturbosch.detekt")
    id("com.google.protobuf")
}

val supportedRustAbis = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "armeabi-v7a" to "armv7-linux-androideabi",
    "x86_64" to "x86_64-linux-android",
)

val configuredRustAbis = (providers.gradleProperty("dsm.android.abis").orNull
    ?: providers.environmentVariable("DSM_ANDROID_ABIS").orNull)
    ?.split(",")
    ?.map { it.trim() }
    ?.filter { it.isNotEmpty() }
    ?.ifEmpty { null }
    ?: supportedRustAbis.keys.toList()

require(configuredRustAbis.all { it in supportedRustAbis }) {
    "Unsupported DSM_ANDROID_ABIS value: ${configuredRustAbis.joinToString(", ")}"
}

android {
    namespace = "com.dsm.wallet"
    compileSdk = 35
    // Pin a known-good NDK for consistency across machines/CI.
    // Must match the NDK version used by cargo-ndk in .cargo/config.toml (r27).
    ndkVersion = "27.0.12077973"

    defaultConfig {
        applicationId = "com.dsm.wallet"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "0.1.0-beta.1"

        // Instrumentation runner for androidTest
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // 16 KB page size support: Native libs built with -Wl,-z,max-page-size=16384
        // See AndroidManifest.xml android:supports_16kb_page_size property
        // Benefits: 3-8% faster app launch, 4.5% lower power draw, 4-6% faster camera
        // If you bundle prebuilt JNI libs in src/main/jniLibs/**, keep ABI listing explicit
        ndk {
            abiFilters += configuredRustAbis
        }

        // CMake build flags for Silicon Fingerprint NDK library
        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
            }
        }
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }
    
    // composeOptions.kotlinCompilerExtensionVersion is managed automatically by
    // org.jetbrains.kotlin.plugin.compose when using Kotlin 2.0.x.

    signingConfigs {
        create("release") {
            val pw = System.getenv("DSM_KEYSTORE_PASSWORD")
            if (pw != null) {
                storeFile = file(System.getenv("DSM_KEYSTORE_PATH") ?: "${System.getProperty("user.home")}/dsm-release.jks")
                storePassword = pw
                keyAlias = System.getenv("DSM_KEY_ALIAS") ?: "dsm-release"
                keyPassword = pw
            }
        }
    }

    buildTypes {
        debug {
            // keep symbols default; avoid AGP version fragility here
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val releaseSigning = signingConfigs.findByName("release")
            if (releaseSigning?.storeFile?.exists() == true) {
                signingConfig = releaseSigning
            }
        }
    }

    // Ensure JNI .so packaging is deterministic
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
        resources {
            excludes += setOf(
                "META-INF/LICENSE*",
                "META-INF/AL2.0",
                "META-INF/LGPL2.1"
            )
        }
    }

    compileOptions {
        // Align with toolchain and remove JDK 24 source/target 8 deprecation warnings
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // Avoid desugaring surprises; keep classic target
        isCoreLibraryDesugaringEnabled = false
    }

    kotlinOptions {
        jvmTarget = "17"
        // Defensive; keeps external @Keep JNI signatures intact
        freeCompilerArgs += listOf("-Xjvm-default=all")
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
        disable += setOf(
            "LintError"  // SinglePathWebViewBridge.kt lint internal crash with DsmNative type
        )
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            // Many Android platform APIs in unit tests don't have real implementations; returning defaults makes tests less flaky
            isReturnDefaultValues = true
        }
    }

    // Make sure src/main/jniLibs is honored (prebuilt .so from cargo-ndk)
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/java")
            jniLibs.srcDir("src/main/jniLibs")
            proto {
                srcDir("../../../proto")
            }
        }
    }

    // NDK C++ build for Silicon Fingerprint (hardware PUF for DBRW)
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:3.25.1"
    }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                create("java")
                create("kotlin")
            }
        }
    }
}

// --- Hard bans to enforce DSM constraints on the Android layer ---
tasks.register("failOnJsonOrB64") {
    doLast {
        // Ban common JSON + Base64 APIs at compile time
        val patterns = listOf(
            // Base64
            "android\\.util\\.Base64",
            "java\\.util\\.Base64",
            "Base64\\.",
            // JSON libs
            "org\\.json\\.",
            "com\\.google\\.gson\\.",
            "Gson",
            "Moshi",
            "kotlinx\\.serialization\\.json",
            "Json\\(",
            "JSONObject",
            "JSONArray",
            "JSONTokener",
            "toJson\\(",
            "fromJson\\("
        )
        val rx = patterns.joinToString("|").toRegex()

        // Ban wall-clock/non-deterministic time sources in app logic
        val timePatterns = listOf(
            "System\\.currentTimeMillis\\(",
            "System\\.nanoTime\\(",
            "java\\.time\\.",
            "new java\\.util\\.Date\\(",
            "new Date\\(",
            "Calendar\\.getInstance\\("
        )
        val timeRx = timePatterns.joinToString("|").toRegex()

        // Ban hex helpers in app logic (Rust side already strict; mirror here)
        val hexPatterns = listOf(
            "\\.toHexString\\(",
            "Hex\\.encode",
            "Hex\\.decode",
            "toHex\\(",
            "fromHex\\("
        )
        val hexRx = hexPatterns.joinToString("|").toRegex()

        fileTree("src").matching {
            include("**/*.kt", "**/*.java")
            exclude("**/build/**")
            // Allow JSON in infrastructure plumbing (event dispatch, MCP serialization)
            exclude("**/EventPoller.kt", "**/McpService.kt")
        }.files.forEach { f ->
            val t = f.readText()
            if (rx.containsMatchIn(t)) {
                throw GradleException("JSON/Base64 API found in ${f.path}. Use protobuf-only transport.")
            }
            // Allow wall-clock time in BleCoordinator for transport-layer rate limiting (CLAUDE.md invariant #4)
            if (timeRx.containsMatchIn(t) && !f.path.contains("BleCoordinator.kt")) {
                throw GradleException("Wall-clock API found in ${f.path}. Use deterministic state counters only.")
            }
            if (hexRx.containsMatchIn(t)) {
                throw GradleException("Hex helper found in ${f.path}. No hex on app layer.")
            }
        }
    }
}

tasks.named("preBuild").configure {
    dependsOn("failOnJsonOrB64")
}


// Disable Kotlin incremental compilation for release tasks to avoid flaky cache/daemon issues.
val isCi = (System.getenv("CI") ?: "").equals("true", ignoreCase = true)
tasks.withType<KotlinCompile>().configureEach {
    if (name.contains("Release", ignoreCase = true) && isCi) {
        incremental = false
    }
}

// ---- Native libs refresh (Rust cargo output -> Android jniLibs) ----
// Prefer cargo's target/<triple> output, but also accept direct cargo-ndk `-o`
// output written into jniLibs. Both are produced by the same Rust build.
val refreshDsmJniLibs = tasks.register("refreshDsmJniLibs") {
    val cargoTarget = project.file("../../deterministic_state_machine/target")
    val appJniLibs = project.file("src/main/jniLibs")
    val repoJniLibs = project.file("../../deterministic_state_machine/jniLibs")

    // ABI -> Rust target triple
    val abiToTriple = configuredRustAbis.associateWith { abi ->
        supportedRustAbis.getValue(abi)
    }

    // Resolve .so path: prefer cargo target release/debug, then accept direct
    // cargo-ndk `-o` output already written into jniLibs.
    fun resolveSo(abi: String, triple: String): File? {
        val release = File(cargoTarget, "$triple/release/libdsm_sdk.so")
        if (release.exists()) return release
        val debug = File(cargoTarget, "$triple/debug/libdsm_sdk.so")
        if (debug.exists()) return debug
        val appOutput = File(File(appJniLibs, abi), "libdsm_sdk.so")
        if (appOutput.exists()) return appOutput
        val repoOutput = File(File(repoJniLibs, abi), "libdsm_sdk.so")
        if (repoOutput.exists()) return repoOutput
        return null
    }

    // Declare cargo target .so files as inputs so Gradle detects rebuilds
    abiToTriple.forEach { (abi, triple) ->
        val so = resolveSo(abi, triple)
        if (so != null) inputs.file(so)
    }
    outputs.dir(appJniLibs)

    doLast {
        fun sha256Hex(f: File): String {
            val md = MessageDigest.getInstance("SHA-256")
            f.inputStream().use { inp ->
                val buf = ByteArray(1024 * 1024)
                while (true) {
                    val n = inp.read(buf)
                    if (n <= 0) break
                    md.update(buf, 0, n)
                }
            }
            return md.digest().joinToString("") { b -> "%02x".format(b) }
        }

        abiToTriple.forEach { (abi, triple) ->
            val src = resolveSo(abi, triple)
            if (src == null) {
                throw GradleException(
                    "Missing Rust build output for $triple (checked release/, debug/, and jniLibs/)\n" +
                    "(hint: run cargo ndk build first)"
                )
            }

            // Copy to app-level jniLibs (what gets packaged)
            val appDst = File(File(appJniLibs, abi), "libdsm_sdk.so")
            appDst.parentFile.mkdirs()
            if (src.canonicalFile != appDst.canonicalFile) {
                src.copyTo(appDst, overwrite = true)
            }

            // Also sync repo-level jniLibs to keep it current
            val repoDst = File(File(repoJniLibs, abi), "libdsm_sdk.so")
            if (repoJniLibs.exists()) {
                repoDst.parentFile.mkdirs()
                if (src.canonicalFile != repoDst.canonicalFile) {
                    src.copyTo(repoDst, overwrite = true)
                }
            }

            val digest = sha256Hex(appDst)
            logger.lifecycle("[DSM JNI] Refreshed $abi/libdsm_sdk.so from ${src.parentFile} sha256=$digest")
        }
    }
}

tasks.named("preBuild").configure {
    dependsOn(refreshDsmJniLibs)
}

// Make Robolectric happy on newer JDKs by opening required modules
tasks.withType<Test>().configureEach {
    jvmArgs(
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "--add-opens=java.base/java.lang.invoke=ALL-UNNAMED",
        "--add-opens=java.base/java.io=ALL-UNNAMED",
        "--add-opens=java.base/java.util=ALL-UNNAMED"
    )
    // Force JDK 17 for Robolectric if available via toolchains (helps avoid JDK 21 incompat)
    val service = project.extensions.findByType(org.gradle.jvm.toolchain.JavaToolchainService::class.java)
    if (service != null) {
        javaLauncher.set(service.launcherFor {
            languageVersion.set(org.gradle.jvm.toolchain.JavaLanguageVersion.of(17))
        })
    }
}

dependencies {
    // Reverted upgrades: latest versions require AGP >=8.6 & compileSdk 36.
    // Keep previous stable versions until AGP/toolchain bump planned.
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.10.0")
    implementation("androidx.webkit:webkit:1.8.0")
    implementation("androidx.work:work-runtime-ktx:2.9.0")
    implementation("no.nordicsemi.android:ble:2.7.1")
    implementation("no.nordicsemi.android:ble-ktx:2.7.1")
    
    // Jetpack Compose (for IncompatibleDeviceScreen and future UI components)
    implementation(platform("androidx.compose:compose-bom:2024.02.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.compose.foundation:foundation")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // ML Kit Barcode Scanning - production-grade QR decoder (replaces html5-qrcode as primary)
    implementation("com.google.mlkit:barcode-scanning:17.2.0")

    // CameraX for consistent camera handling across device stacks
    val cameraxVersion = "1.3.1"
    implementation("androidx.camera:camera-core:$cameraxVersion")
    implementation("androidx.camera:camera-camera2:$cameraxVersion")
    implementation("androidx.camera:camera-lifecycle:$cameraxVersion")
    implementation("androidx.camera:camera-view:$cameraxVersion")

    // Protobuf for envelope generation
    implementation("com.google.protobuf:protobuf-kotlin:3.25.1")

    // Unit test deps (Robolectric so we can run Android-like tests without a device)
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.11.1")
    testImplementation("androidx.test:core:1.5.0")
    // MockWebServer for exercising localhost proxy logic
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")

    // Mockito for mocking final classes and Kotlin-friendly APIs
    testImplementation("org.mockito:mockito-inline:5.2.0")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.1.0")
    // Coroutines test utilities for concurrency checks
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")

    // Instrumentation test deps (run on device/emulator)
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.5.2")
    androidTestImplementation("androidx.test:rules:1.5.0")
    androidTestImplementation("androidx.test:core:1.5.0")
    androidTestImplementation("junit:junit:4.13.2")
}

// --- Jacoco coverage for unit tests (debug) ---
jacoco {
    toolVersion = "0.8.10"
}

tasks.withType<Test>().configureEach {
    extensions.configure(JacocoTaskExtension::class.java) {
        isIncludeNoLocationClasses = true
        excludes = listOf("jdk.internal.*")
    }
}

tasks.register<JacocoReport>("jacocoTestReport") {
    group = "verification"
    description = "Generates Jacoco coverage report for unit tests (debug)."
    dependsOn("testDebugUnitTest")

    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(false)
    }

    val debugTree = fileTree(
        mapOf(
            "dir" to layout.buildDirectory.dir("tmp/kotlin-classes/debug").get().asFile,
            "excludes" to listOf(
                "**/R.class",
                "**/R$*.class",
                "**/BuildConfig.*",
                "**/Manifest*.*",
                "**/*Test*.*"
            )
        )
    )
    val javaDebugTree = fileTree(
        mapOf(
            "dir" to layout.buildDirectory.dir("intermediates/javac/debug/classes").get().asFile,
            "excludes" to listOf(
                "**/R.class",
                "**/R$*.class",
                "**/BuildConfig.*",
                "**/Manifest*.*",
                "**/*Test*.*"
            )
        )
    )

    classDirectories.setFrom(files(debugTree, javaDebugTree))
    sourceDirectories.setFrom(files("src/main/java", "src/main/kotlin"))

    val execFile = layout.buildDirectory.file("jacoco/testDebugUnitTest.exec").get().asFile
    executionData.setFrom(files(execFile).filter { it.exists() })
}

// --- Developer convenience tasks to make local multi-node usage automatic ---

// Reverse-map local storage-node ports on all connected devices
tasks.register("reverseStoragePorts") {
    group = "dsm-dev"
    description = "ADB reverse 8080-8084 on all connected devices"
    doLast {
        val adb = "adb"
        val baos = ByteArrayOutputStream()
        providers.exec {
            commandLine(adb, "devices", "-l")
            standardOutput = baos
            isIgnoreExitValue = true
        }
        val out = baos.toString()
        val serials: List<String> = out
            .lineSequence()
            .map { line -> line.trim() }
            .filter { line -> line.isNotEmpty() }
            .filter { line -> !line.startsWith("List of devices") }
            .filter { line -> line.contains("\tdevice") || line.endsWith(" device") }
            .map { line -> line.split("\t", " ", limit = 2).first().trim() }
            .filter { line -> line.isNotEmpty() }
            .toList()

        if (serials.isEmpty()) {
            logger.lifecycle("No devices detected for reverse ports")
        } else {
            serials.forEach { serial ->
                listOf("8080", "8081", "8082", "8083", "8084").forEach { port ->
                    try {
                        providers.exec { commandLine(adb, "-s", serial, "reverse", "tcp:$port", "tcp:$port") }
                        logger.lifecycle("Reversed tcp:$port on $serial")
                    } catch (t: Throwable) {
                        logger.warn("Failed to reverse tcp:$port on $serial: ${'$'}{t.message}")
                    }
                }
            }
        }
    }
}

// Install debug then reverse ports in one go
tasks.register("installDebugAndReverse") {
    group = "dsm-dev"
    description = "Install debug APK and reverse ports 8080-8084"
    dependsOn("installDebug")
    finalizedBy("reverseStoragePorts")
}

// Optional: start the app on all devices
tasks.register("startAppOnAllDevices") {
    group = "dsm-dev"
    description = "Start com.dsm.wallet MainActivity on all connected devices"
    doLast {
        val adb = "adb"
        val baos = ByteArrayOutputStream()
        providers.exec {
            commandLine(adb, "devices", "-l")
            standardOutput = baos
            isIgnoreExitValue = true
        }
        val out = baos.toString()
        val serials: List<String> = out
            .lineSequence()
            .map { line -> line.trim() }
            .filter { line -> line.isNotEmpty() }
            .filter { line -> !line.startsWith("List of devices") }
            .filter { line -> line.contains("\tdevice") || line.endsWith(" device") }
            .map { line -> line.split("\t", " ", limit = 2).first().trim() }
            .filter { line -> line.isNotEmpty() }
            .toList()

        serials.forEach { serial ->
            try {
                providers.exec { commandLine(adb, "-s", serial, "shell", "am", "start", "-n", "com.dsm.wallet/.ui.MainActivity") }
                logger.lifecycle("Launched app on $serial")
            } catch (t: Throwable) {
                logger.warn("Failed to start app on $serial: ${'$'}{t.message}")
            }
        }
    }
}

// --- Detekt static analysis for Kotlin ---
detekt {
    config.setFrom(files("${rootProject.projectDir}/detekt.yml"))
    buildUponDefaultConfig = true
    parallel = true
    source.setFrom(files("src/main/java"))
}
