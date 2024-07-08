import uk.gov.securestore.config.ApkConfig

plugins {
    `maven-publish`
    id("uk.gov.securestore.android-lib-config")
}

android {
    defaultConfig {
        namespace = ApkConfig.APPLICATION_ID + ".impl"
        compileSdk = ApkConfig.COMPILE_SDK_VERSION
        minSdk = ApkConfig.MINIMUM_SDK_VERSION
        targetSdk = ApkConfig.TARGET_SDK_VERSION
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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

publishing {
    publications {
        create<MavenPublication>("mobile-android-secure-store") {
            groupId = "uk.gov.android"
            artifactId = "securestore"
            version = rootProject.extra["packageVersion"] as String

            artifact("$buildDir/outputs/aar/${project.name}-release.aar")

            // generate pom nodes for dependencies
            pom.withXml {
                val dependenciesNode = asNode().appendNode("dependencies")
                configurations.getByName("implementation") {
                    allDependencies.forEach { dependency ->
                        if (dependency.name != "unspecified") {
                            val dependencyNode = dependenciesNode.appendNode("dependency")
                            dependencyNode.appendNode("groupId", dependency.group)
                            dependencyNode.appendNode("artifactId", dependency.name)
                            dependencyNode.appendNode("version", dependency.version)
                        }
                    }
                }
            }
        }
        repositories {
            maven("https://maven.pkg.github.com/govuk-one-login/mobile-android-secure-store") {
                credentials {
                    username = System.getenv("GITHUB_ACTOR")
                    password = System.getenv("GITHUB_TOKEN")
                }
            }
        }
    }
}
