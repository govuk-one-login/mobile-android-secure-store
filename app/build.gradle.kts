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
        targetSdk = apkConfig.sdkVersions.target
        testInstrumentationRunner = "$namespace.InstrumentationTestRunner"
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

    lint {
        val configDir = "${rootProject.projectDir}/config"

        abortOnError = true
        absolutePaths = true
        baseline = File("$configDir/android/baseline.xml")
        checkAllWarnings = true
        checkDependencies = false
        checkGeneratedSources = false
        checkReleaseBuilds = true
        disable.addAll(
            setOf(
                "ConvertToWebp",
                "UnusedIds",
                "VectorPath",
            ),
        )
        explainIssues = true
        htmlReport = true
        ignoreTestSources = true
        ignoreWarnings = false
        lintConfig = File("$configDir/android/lint.xml")
        noLines = false
        quiet = false
        showAll = true
        textReport = true
        warningsAsErrors = true
        xmlReport = true
    }

    testOptions {
        execution = "ANDROIDX_TEST_ORCHESTRATOR"
        animationsDisabled = true
        unitTests.all {
            it.testLogging {
                events =
                    setOf(
                        org.gradle.api.tasks.testing.logging.TestLogEvent.FAILED,
                        org.gradle.api.tasks.testing.logging.TestLogEvent.PASSED,
                        org.gradle.api.tasks.testing.logging.TestLogEvent.SKIPPED,
                    )
            }
        }
        unitTests {
            isReturnDefaultValues = true
            isIncludeAndroidResources = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
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
        libs.androidx.test,
        libs.junit,
        libs.mockito,
        libs.mockito.kotlin,
    ).forEach(::testImplementation)
}

mavenPublishingConfig {
    mavenConfigBlock {
        name.set(
            "secure storage of key-value data"
        )
        description.set(
            """
                Gradle configured Android library for secure storage of data, optionally protected by the user’s biometrics & passcode
            """.trimIndent()
        )


    }
}