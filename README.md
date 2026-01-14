# mobile-android-secure-storage

[![On Branch Push (main)](https://github.com/govuk-one-login/mobile-android-secure-store/actions/workflows/on_push-main.yml/badge.svg)](https://github.com/govuk-one-login/mobile-android-secure-store/actions/workflows/on_push-main.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mobile-android-secure-store&metric=alert_status&token=83ba0683800aaef95a5e945919d235f1abd8ac6d)](https://sonarcloud.io/summary/new_code?id=mobile-android-secure-store)

Implementation of a secure storage solution for Android.

This will allow consumers to `save` `query` and `delete` key value data saved in shared preferences.
The data will be encrypted before storage and decrypted on retrieval, when an instance is created the consumer can choose the access level of the data (are biometrics required to access)

## Updating gradle-wrapper

Gradle secure hash algorithm (SHA) pinning is in place through the `distributionSha256Sum` attribute in gradle-wrapper.properties. This means the gradle-wrapper must upgrade through the `./gradlew wrapper` command.
Example gradle-wrapper.properties
```
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionSha256Sum=2db75c40782f5e8ba1fc278a5574bab070adccb2d21ca5a6e5ed840888448046
distributionUrl=https\://services.gradle.org/distributions/gradle-8.10.2-bin.zip
networkTimeout=10000
validateDistributionUrl=true
 ```

Use the following command to update the gradle wrapper. Run the same command twice, [reason](https://sp4ghetticode.medium.com/the-elephant-in-the-room-how-to-update-gradle-in-your-android-project-correctly-09154fe3d47b).

```bash
./gradlew wrapper --gradle-version=8.10.2 --distribution-type=bin --gradle-distribution-sha256-sum=31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26
```

Flags:
- `gradle-version` self explanatory
- `distribution-type` set to `bin` short for binary refers to the gradle bin, often in this format `gradle-8.10.2-bin.zip`
- `gradle-distribution-sha256-sum` the SHA 256 checksum from this [page](https://gradle.org/release-checksums/), pick the binary checksum for the version used

The gradle wrapper update can include:
- gradle-wrapper.jar
- gradle-wrapper.properties
- gradlew
- gradlew.bat

You can use the following command to check the SHA 256 checksum of a file

```bash
shasum -a 256 gradle-8.10.2-bin.zip
```
## Usage

Add to your version catalog as per below:

```
secure-store = { group = "uk.gov.securestore", name = "app", version = "0.8.0" }
```

## Hotfix changes
There are GitHub Actions workflows for a hotfix pull request and merging a hotfix to a temporary
hotfix branch.

The temporary hotfix branch is currently expected to be named "temp/hotfix". If a different name is
desired please edit the value under "branches:" in `.github/workflows/on_push_hotfix.yml`.
The hotfix branch name should be in the format "hotfix/M.m.p".

Once the hotfix PR has been approved and the "Squash and merge" button pressed, the merge title
must be in the format "Merge pull request #xxx from govuk-one-login/release/M.m.p" to allow for the
correct version to be extracted and used as a tag.
