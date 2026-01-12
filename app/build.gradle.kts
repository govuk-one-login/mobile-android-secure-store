import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import uk.gov.pipelines.config.ApkConfig

plugins {
    id("uk.gov.pipelines.android-lib-config")
}

android {
    defaultConfig {
        val apkConfig: ApkConfig by project.rootProject.extra
        namespace = apkConfig.applicationId + ".impl"
        compileSdk = apkConfig.sdkVersions.compile
        minSdk = apkConfig.sdkVersions.minimum
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    testOptions {
        execution = "ANDROIDX_TEST_ORCHESTRATOR"
        animationsDisabled = true
        unitTests.all {
            it.useJUnitPlatform()
            it.testLogging {
                events =
                    setOf(
                        TestLogEvent.FAILED,
                        TestLogEvent.PASSED,
                        TestLogEvent.SKIPPED,
                    )
            }
        }
        unitTests {
            isReturnDefaultValues = true
            isIncludeAndroidResources = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin {
        compilerOptions {
            jvmTarget = JvmTarget.JVM_17
        }
    }
    ktlint {
        version = libs.versions.ktlint.cli.get()
    }
}

dependencies {
    listOf(
        libs.androidx.test.ext.junit,
        libs.androidx.test.runner,
        libs.androidx.test.rules,
        libs.espresso.core,
        libs.mockito,
        libs.mockito.kotlin,
        libs.mockito.android,
    ).forEach(::androidTestImplementation)

    listOf(
        libs.core.ktx,
        libs.androidx.biometric,
        libs.appcompat,
    ).forEach(::implementation)

    listOf(
        kotlin("test"),
        kotlin("test-junit5"),
        libs.bundles.test,
        platform(libs.junit.bom),
        libs.androidx.test,
        libs.mockito,
        libs.mockito.kotlin,
        libs.kotlinx.coroutines.test,
    ).forEach(::testImplementation)

    listOf(
        libs.androidx.test.orchestrator,
    ).forEach {
        androidTestUtil(it)
    }
}

mavenPublishingConfig {
    mavenConfigBlock {
        name.set(
            "secure storage of key-value data",
        )
        description.set(
            """
                Gradle configured Android library for secure storage of data, optionally protected by the user’s biometrics & passcode
            """.trimIndent(),
        )
    }
}
