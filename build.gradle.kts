import uk.gov.pipelines.config.ApkConfig
import uk.gov.pipelines.emulator.EmulatorConfig
import uk.gov.pipelines.emulator.SystemImageSource

buildscript {
    val buildLogicDir: String by rootProject.extra("mobile-android-pipelines/buildLogic")

    // Github packages publishing configuration
    val githubRepositoryName: String by rootProject.extra("mobile-android-secure-store")
    val mavenGroupId: String by rootProject.extra("uk.gov.securestore")
    // Sonar configuration
    val sonarProperties: Map<String, String> by rootProject.extra(
        mapOf(
            "sonar.projectKey" to "mobile-android-secure-store",
            "sonar.projectName" to "mobile-android-secure-store"
        )
    )

    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

val apkConfig by rootProject.extra(
    object: ApkConfig {
        override val applicationId: String = "uk.gov.securestore"
        override val debugVersion: String = "DEBUG_VERSION"
        override val sdkVersions = object: ApkConfig.SdkVersions {
            override val minimum = 29
            override val target = 33
            override val compile = 34
        }
    }
)

val emulatorConfig by rootProject.extra(
    EmulatorConfig(
        systemImageSources = setOf(SystemImageSource.GOOGLE_ATD),
        androidApiLevels = setOf(33),
        deviceFilters = setOf("Pixel XL"),
    )
)

plugins {
    id("uk.gov.pipelines.vale-config")
    id("uk.gov.pipelines.sonarqube-root-config")
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
}