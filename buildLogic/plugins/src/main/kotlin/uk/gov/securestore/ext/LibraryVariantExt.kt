package uk.gov.securestore.ext

import com.android.build.gradle.api.LibraryVariant
import org.gradle.api.Project
import org.gradle.configurationcache.extensions.capitalized
import uk.gov.securestore.filetree.fetcher.AsmFileTreeFetcher
import uk.gov.securestore.filetree.fetcher.FileTreesFetcher
import uk.gov.securestore.filetree.fetcher.JavaCompileFileTreeFetcher
import uk.gov.securestore.filetree.fetcher.KotlinCompileFileTreeFetcher
import uk.gov.securestore.jacoco.tasks.JacocoCombinedTestTaskGenerator
import uk.gov.securestore.jacoco.tasks.JacocoConnectedTestTaskGenerator
import uk.gov.securestore.jacoco.tasks.JacocoTaskGenerator
import uk.gov.securestore.jacoco.tasks.JacocoUnitTestTaskGenerator

fun LibraryVariant.generateDebugJacocoTasks(
    project: Project
) {
    val capitalisedFlavorName = flavorName.capitalized()
    if (buildType.name == "debug") {
        val classDirectoriesFetcher = FileTreesFetcher(
            project,
            KotlinCompileFileTreeFetcher(
                project,
                name,
                capitalisedFlavorName,
            ),
            AsmFileTreeFetcher(
                project,
                name,
                capitalisedFlavorName,
            ),
            JavaCompileFileTreeFetcher(
                project,
                name,
                capitalisedFlavorName,
            ),
        )

        val unitTestReportGenerator = JacocoUnitTestTaskGenerator(
            project,
            classDirectoriesFetcher,
            name,
        )

        val connectedTestReportGenerator = JacocoConnectedTestTaskGenerator(
            project,
            classDirectoriesFetcher,
            name,
        )

        val combinedTestReportGenerator = JacocoCombinedTestTaskGenerator(
            project = project,
            classDirectoriesFetcher = classDirectoriesFetcher,
            variant = name,
            configurations = listOf(
                unitTestReportGenerator,
                connectedTestReportGenerator,
            ),
        )

        listOf(
            unitTestReportGenerator,
            connectedTestReportGenerator,
            combinedTestReportGenerator,
        ).forEach(JacocoTaskGenerator::customTask)
    }
}