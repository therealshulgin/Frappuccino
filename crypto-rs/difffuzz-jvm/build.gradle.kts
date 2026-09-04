plugins {
    kotlin("jvm") version "1.9.24"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // UniFFI 0.28 Kotlin bindings marshal via JNA — the SAME path as Android,
    // so a desktop-JVM run faithfully exercises the device's glue code.
    implementation("net.java.dev.jna:jna:5.14.0")
    // Minimal JSON reader for the JSONL corpus emitted by the Rust dumper.
    implementation("org.json:json:20240303")
}

application {
    // Reads the JSONL corpus (arg 0, or ./difffuzz-corpus.jsonl), replays each
    // case through the UniFFI bindings, diffs against the recorded Rust outcome.
    mainClass.set("MainKt")
}

// The generated UniFFI bindings (src/main/kotlin/uniffi/frappuccino/) call
// `Native.load("uniffi_frappuccino")`; JNA resolves the .dll/.so from
// jna.library.path. It's built by `cargo build -p frappuccino-crypto-ffi` into
// ../target/debug. Regenerate the bindings after any UDL change with:
//   cargo run -p frappuccino-crypto-ffi --bin uniffi-bindgen -- \
//     generate ffi/src/frappuccino.udl --language kotlin \
//     --out-dir difffuzz-jvm/src/main/kotlin
tasks.named<JavaExec>("run") {
    systemProperty(
        "jna.library.path",
        layout.projectDirectory.dir("../target/debug").asFile.absolutePath,
    )
}
