// Standalone Gradle build for the Kotlin<->Rust differential-fuzz harness
// (ROADMAP 8.4 item 3). NOT part of the Android Gradle build (root
// settings.gradle) nor the cargo workspace — its own self-contained project so
// it can run the generated UniFFI bindings on the desktop JVM (same JNA
// marshalling as Android) against the corpus emitted by `frappuccino-difffuzz-dump`.
rootProject.name = "difffuzz-jvm"
