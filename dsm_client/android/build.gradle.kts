// <repo-root>/build.gradle.kts
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        // Bridge detekt + AGP into the same classloader so detekt's AndroidExtension
        // hooks can resolve BaseExtension under Gradle 8.9+ isolation rules.
        classpath("com.android.tools.build:gradle:8.7.3")
        classpath("io.gitlab.arturbosch.detekt:detekt-gradle-plugin:1.23.7")
    }
}

plugins {
    id("io.gitlab.arturbosch.detekt") version "1.23.7" apply false
}


subprojects {

    /* give every module a Java 17 tool-chain – Android Gradle
       plugin automatically applies 'java' for us                */
    plugins.withType<JavaPlugin>().configureEach {
        the<JavaPluginExtension>().toolchain {
            languageVersion.set(JavaLanguageVersion.of(17))
        }
    }
}
