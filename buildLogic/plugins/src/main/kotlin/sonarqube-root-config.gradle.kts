import org.sonarqube.gradle.SonarExtension

plugins {
    id("org.sonarqube")
}

/**
 * Defined within the git repository's `build.gradle.kts` file
 */
val packageVersion: String by rootProject.extra

val rootSonarProperties by rootProject.extra(
    mapOf(
        "sonar.host.url" to System.getProperty("uk.gov.android.securestore.sonar.host.url"),
        "sonar.token" to System.getProperty("uk.gov.android.securestore.sonar.login"),
        "sonar.projectKey" to "mobile-android-secure-store",
        "sonar.projectName" to "mobile-android-secure-store",
        "sonar.projectVersion" to packageVersion,
        "sonar.organization" to "govuk-one-login",
        "sonar.sourceEncoding" to "UTF-8",
    ),
)

configure<SonarExtension> {
    this.setAndroidVariant("debug")

    properties {
        rootSonarProperties.forEach { (key, value) ->
            property(key, value)
        }
    }
}
