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
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven {
            name = "SignalBuildArtifacts"
            url = uri("https://build-artifacts.signal.org/libraries/maven/")
            content {
                includeGroupByRegex("org\\.signal.*")
            }
        }
    }
}

rootProject.name = "Umoja Secure"
include(":app")
 