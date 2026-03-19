/* -------------------------------------------------------------- *
 *  settings.gradle.kts  ––  the single source of plugin versions *
 * -------------------------------------------------------------- */

pluginManagement {

    /*  where Gradle should look for the actual artefacts            */
    repositories {
        google()          // Android Gradle Plugin, KSP
        mavenCentral()
        gradlePluginPortal()
    }

    /*  pin every plugin that any sub-project may ask for            */
    /*  NOTE: Toolchain lock (Feb 2026)                              */
    /*  AGP 8.7.3 + Kotlin 2.0.21 + KSP 2.0.21-1.0.28               */
    /*  Kotlin 2.0.21 fixes BuildFlowService serialization (Gradle 8.9+). */
    plugins {
        id("com.android.application")                  version "8.7.3"
        id("org.jetbrains.kotlin.android")             version "2.0.21"
        id("org.jetbrains.kotlin.kapt")                version "2.0.21"
        id("org.jetbrains.kotlin.plugin.compose")      version "2.0.21"
        id("com.google.dagger.hilt.android")           version "2.51.1"
        id("com.google.devtools.ksp")                  version "2.0.21-1.0.28"
        id("com.google.protobuf")                      version "0.9.4"
    }
}

/*  All ordinary (library) dependencies are resolved from here      */
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "DSM Wallet"
include(":app")