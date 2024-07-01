package uk.gov.securestore

import com.android.build.api.dsl.LibraryExtension
import com.android.build.gradle.BaseExtension
import uk.gov.securestore.extensions.BaseExtensions.baseAndroidConfig
import uk.gov.securestore.extensions.LintExtensions.configureLintOptions

listOf(
    "com.android.library",
    "kotlin-kapt",
    "org.jetbrains.kotlin.android",
    "uk.gov.securestore.detekt-config",
    "uk.gov.securestore.emulator-config",
    "uk.gov.securestore.jacoco-lib-config",
    "uk.gov.securestore.jvm-toolchains",
    "uk.gov.securestore.ktlint-config",
    "uk.gov.securestore.sonarqube-module-config"
).forEach {
    project.plugins.apply(it)
}

configure<BaseExtension> {
    baseAndroidConfig(project)
}

configure<LibraryExtension> {
    lint(configureLintOptions("${rootProject.projectDir}/config"))
}
