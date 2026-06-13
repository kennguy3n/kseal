pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "kseal-android-quickstart"

// Build the kseal Android SDK from source as a composite build, so the sample
// always tracks the SDK on `main`. Gradle substitutes the `io.kseal:kseal-android`
// dependency below with this included build automatically.
includeBuild("../../sdk/android")

include(":app")
