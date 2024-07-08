package uk.gov.securestore

import com.android.build.gradle.LibraryExtension
import uk.gov.securestore.extensions.LibraryExtensionExt.decorateExtensionWithJacoco
import uk.gov.securestore.extensions.ProjectExtensions.debugLog
import uk.gov.securestore.extensions.generateDebugJacocoTasks
import com.android.build.api.dsl.LibraryExtension as DslLibraryExtension

project.plugins.apply("uk.gov.securestore.jacoco-common-config")

val depJacoco: String by rootProject.extra

project.configure<DslLibraryExtension> {
    decorateExtensionWithJacoco(depJacoco).also {
        project.debugLog("Applied jacoco properties to Library")
    }
}

project.configure<LibraryExtension> {
    decorateExtensionWithJacoco(depJacoco).also {
        project.debugLog("Applied jacoco properties to Library")
    }
}

project.afterEvaluate {
    (this.findProperty("android") as? LibraryExtension)?.let { extension ->
        extension.libraryVariants.all {
            generateDebugJacocoTasks(project)
        }
    }
}
