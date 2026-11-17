# Contributing to the GOV.UK One Login secure store for Android

## Set up the project

1. Clone the repository with its submodule. The build uses shared configuration from [mobile-android-pipelines](https://github.com/govuk-one-login/mobile-android-pipelines).

    ```bash
    git clone --recurse-submodules https://github.com/govuk-one-login/mobile-android-secure-store.git
    ```

    If you have already cloned it without the submodule, run:

    ```bash
    git submodule update --init
    ```

2. Open the project in Android Studio and let Gradle sync.

3. Run the unit tests to check everything works.

    ```bash
    ./gradlew testDebugUnitTest
    ```

## Make changes

- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages. The rules are in `git-conventional-commits.yaml` and `cog.toml`, and the hooks in `.githooks` check them.
- Run the unit tests, and the instrumented tests if you change anything that touches the Android Keystore or the biometric prompt:

    ```bash
    ./gradlew testDebugUnitTest
    ./gradlew connectedDebugAndroidTest
    ```

- Do not change `KEY_SUFFIX` in `SharedPrefsStoreAsyncV2`. Changing it makes data saved by existing app installs unreadable.

## Update the Gradle wrapper

The Gradle distribution is pinned with a SHA-256 checksum through the `distributionSha256Sum` property in `gradle/wrapper/gradle-wrapper.properties`. For example:

```properties
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionSha256Sum=2db75c40782f5e8ba1fc278a5574bab070adccb2d21ca5a6e5ed840888448046
distributionUrl=https\://services.gradle.org/distributions/gradle-8.10.2-bin.zip
networkTimeout=10000
validateDistributionUrl=true
```

This means you must update the wrapper with the `./gradlew wrapper` command:

1. Find the binary checksum for the Gradle version you want on the [Gradle release checksums page](https://gradle.org/release-checksums/).

2. Run the following command twice. The [second run updates the wrapper JAR and scripts](https://sp4ghetticode.medium.com/the-elephant-in-the-room-how-to-update-gradle-in-your-android-project-correctly-09154fe3d47b).

    ```bash
    ./gradlew wrapper --gradle-version=8.10.2 --distribution-type=bin --gradle-distribution-sha256-sum=31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26
    ```

| Flag | Description |
| --- | --- |
| `--gradle-version` | The Gradle version to use |
| `--distribution-type` | Set to `bin`, the binary distribution, for example `gradle-8.10.2-bin.zip` |
| `--gradle-distribution-sha256-sum` | The SHA-256 checksum of the binary distribution |

The update can change:

- `gradle/wrapper/gradle-wrapper.jar`
- `gradle/wrapper/gradle-wrapper.properties`
- `gradlew`
- `gradlew.bat`

To check the checksum of a downloaded distribution yourself, run:

```bash
shasum -a 256 gradle-8.10.2-bin.zip
```

## Release a hotfix

GitHub Actions workflows handle hotfix pull requests and merges to a temporary hotfix branch.

1. The temporary hotfix branch must be called `temp/hotfix`. To use a different name, change the value under `branches:` in `.github/workflows/on_push_hotfix.yml`.

2. Name the hotfix branch in the format `hotfix/M.m.p`, for example `hotfix/2.0.2`.

3. When the hotfix pull request is approved, select **Squash and merge**. The merge title must be in the format:

    ```
    Merge pull request #xxx from govuk-one-login/release/M.m.p
    ```

    The workflow reads the version from this title and uses it to tag the release.

