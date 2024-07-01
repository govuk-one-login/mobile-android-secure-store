package uk.gov.securestore.jacoco.tasks

import org.gradle.api.Project
import org.gradle.configurationcache.extensions.capitalized
import uk.gov.securestore.Filters
import uk.gov.securestore.filetree.fetcher.FileTreeFetcher
import uk.gov.securestore.jacoco.config.JacocoConnectedTestConfig
import uk.gov.securestore.jacoco.config.JacocoCustomConfig

/**
 * A [JacocoTaskGenerator] implementation specifically for instrumentation tests.
 *
 * @param project The Gradle [Project] that houses the generated Jacoco task. Used to generate the
 * relevant [JacocoCustomConfig] instance.
 * @param classDirectoriesFetcher The [FileTreeFetcher] that provides the class directories used for
 * reporting code coverage through Jacoco.
 * @param variant The name of the build variant. Used as a parameter to obtain relevant Gradle
 * tasks.
 */
class JacocoConnectedTestTaskGenerator(
    private val project: Project,
    private val classDirectoriesFetcher: FileTreeFetcher,
    variant: String,
    name: String = "jacoco${variant.capitalized()}ConnectedTestReport",
    configuration: JacocoCustomConfig = JacocoConnectedTestConfig(
        project,
        classDirectoriesFetcher,
        variant.capitalized(),
        name
    )
) : BaseJacocoTaskGenerator(
    project,
    variant,
    configuration
) {

    override val androidCoverageTaskName: String =
        "create${capitalisedVariantName}AndroidTestCoverageReport"
    override val description =
        "Create coverage report from the '$capitalisedVariantName' instrumentation tests."
    override val reportsBaseDirectory: String get() = "$reportsDirectoryPrefix/connected"
    override val testTaskName: String get() = "connected${capitalisedVariantName}AndroidTest"
    override val excludes: List<String> = Filters.androidInstrumentationTests
}
