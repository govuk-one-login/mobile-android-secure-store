buildscript {
    val jacocoVersion by rootProject.extra("0.8.9")
    val baseNamespace by rootProject.extra { "uk.gov.android.securestore" }

    val localProperties = java.util.Properties()
    if (rootProject.file("local.properties").exists()) {
        println(localProperties)
        localProperties.load(java.io.FileInputStream(rootProject.file("local.properties")))
    }

    fun findPackageVersion(): String {
        var version = "1.0.0"

        if (rootProject.hasProperty("packageVersion")) {
            version = rootProject.property("packageVersion") as String
        } else if (localProperties.getProperty("packageVersion") != null) {
            version = localProperties.getProperty("packageVersion") as String
        }

        return version
    }

    val packageVersion by rootProject.extra { findPackageVersion() }

    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

plugins {
    id("uk.gov.securestore.vale-config")
    id("uk.gov.securestore.sonarqube-root-config")
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
}
