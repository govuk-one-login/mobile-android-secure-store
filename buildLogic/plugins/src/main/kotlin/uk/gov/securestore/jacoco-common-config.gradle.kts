package uk.gov.securestore

import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.extra
import org.gradle.kotlin.dsl.jacoco
import org.gradle.kotlin.dsl.withType
import org.gradle.testing.jacoco.plugins.JacocoPluginExtension
import uk.gov.securestore.extensions.ProjectExtensions.debugLog
import uk.gov.securestore.extensions.TestExt.decorateTestTasksWithJacoco

plugins {
    jacoco
}

val depJacoco: String by rootProject.extra("0.8.8")

project.configure<JacocoPluginExtension> {
    this.toolVersion = depJacoco
    project.logger.debug("Applied jacoco tool version to jacoco plugin")
}

project.tasks.withType<Test> {
    decorateTestTasksWithJacoco().also {
        project.debugLog("Applied jacoco properties to Test tasks")
    }
}
