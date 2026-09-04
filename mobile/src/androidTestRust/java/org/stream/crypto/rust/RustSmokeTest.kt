package org.stream.crypto.rust

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.frappuccino.coreVersion
import uniffi.frappuccino.helloWorld

/**
 * Verifies the Kotlin↔Rust UniFFI bridge is wired end-to-end.
 *
 * Needs the Rust build first. There is no flag to opt in or out: this file is
 * always compiled, `mobile/build.gradle` adding `src/androidTestRust/java` to
 * the androidTest sources unconditionally. It only passes once
 * `./gradlew :mobile:rustBuild` has produced the `.so` and the generated
 * `uniffi.frappuccino.*` bindings under
 * `stream-crypto/build/generated/source/uniffi/debug/java/`; without the `.so`
 * it fails on native loading rather than on anything it asserts.
 *
 * Run:
 * ```
 * ./gradlew :mobile:rustBuild
 * ./gradlew :mobile:connectedAndroidTest \
 *     --tests 'org.stream.crypto.rust.RustSmokeTest'
 * ```
 *
 * Past loading the `.so` and proxying a String across FFI, what the second
 * assertion adds is the reason it exists: `coreVersion` only returns at all if
 * the FFI crate reaches `frappuccino-crypto-core`, which is what confirms the
 * workspace's inter-crate linking works on the Android target (S0).
 */
@RunWith(AndroidJUnit4::class)
class RustSmokeTest {

    @Test
    fun helloWorld_returnsExpectedGreeting() {
        assertEquals("hello from rust via uniffi (S0)", helloWorld())
    }

    @Test
    fun coreVersion_isNonEmpty() {
        val v = coreVersion()
        assertTrue("core_version must be non-empty, got '$v'", v.isNotEmpty())
        // Loose sanity: version looks like semver x.y.z
        assertTrue("core_version should contain dots, got '$v'", v.contains("."))
    }
}
