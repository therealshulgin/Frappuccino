package rs.readahead.washington.mobile.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.stream.crypto.StreamIdentity

/**
 * The redaction rules every diagnostics line goes through. One case that must
 * be redacted and one that must not, per rule, at the thresholds themselves
 * where there is one. Main source set on purpose: these run in every build,
 * production versions included.
 */
class LogRedactorTest {

    private fun r(line: String) = LogRedactor.redact(line)

    @Test
    fun `the French BIP-39 list is loaded whole`() {
        assertEquals(2048, LogRedactor.wordCount)
    }

    // ---- hex ----

    @Test
    fun `16 hex digits are redacted, 15 are not`() {
        assertEquals("id=<hex> end", r("id=0123456789abcdef end"))
        assertEquals("id=0123456789abcde end", r("id=0123456789abcde end"))
    }

    @Test
    fun `a session id in an envelope name is redacted, the sequence number kept`() {
        assertEquals(
            "sealed <hex>_000001.env",
            r("sealed 0123456789abcdef0123456789ABCDEF_000001.env"),
        )
    }

    // ---- grouped hex ----

    @Test
    fun `the identity's fingerprint as the app writes it is redacted`() {
        val identity = StreamIdentity(ByteArray(32) { it.toByte() }, ByteArray(32))
        val fingerprint = identity.readableFingerprint()
        assertEquals(6, fingerprint.split(' ').size)
        assertEquals("enrolled, fingerprint: <hex> ok", r("enrolled, fingerprint: $fingerprint ok"))
    }

    @Test
    fun `grouped hex is redacted from 16 digits, not at 15`() {
        assertEquals("fp <hex> end", r("fp 3fa9 07c1 be42 9d10 end"))
        assertEquals("fp 3fa9 07c1 be42 9d1 end", r("fp 3fa9 07c1 be42 9d1 end"))
        // Ten groups: eight in this form would be an IPv6 address, and go as one.
        assertEquals("sha <hex>", r("sha AB:CD:EF:01:23:45:67:89:AB:CD"))
        assertEquals("id <hex>.", r("id a1b2-c3d4-e5f6-a7b8."))
    }

    @Test
    fun `numbers and dates in groups stay below the threshold`() {
        assertEquals("fps 15 30 24 30 60 60", r("fps 15 30 24 30 60 60"))
        assertEquals("at 2026-10-29 14:03:12 done", r("at 2026-10-29 14:03:12 done"))
    }

    // ---- UUID ----

    @Test
    fun `a UUID is redacted, a truncated one is not`() {
        assertEquals("work <uuid> done", r("work 123e4567-e89b-12d3-a456-426614174000 done"))
        assertEquals("work 123e4567-e89b-12d3-a456 done", r("work 123e4567-e89b-12d3-a456 done"))
    }

    // ---- JWT ----

    @Test
    fun `a JWT is redacted, a lone eyJ prefix is not`() {
        assertEquals(
            "token <jwt> sent",
            r("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl_-x sent"),
        )
        assertEquals("prefix eyJhbG only", r("prefix eyJhbG only"))
    }

    // ---- base64 ----

    @Test
    fun `40 base64 characters are redacted, 39 are not`() {
        val b40 = "Zq9+".repeat(10)
        assertEquals(40, b40.length)
        assertEquals("key=<b64> ok", r("key=$b40 ok"))
        assertEquals("key=${b40.take(39)} ok", r("key=${b40.take(39)} ok"))
    }

    @Test
    fun `base64url and padding are redacted with the run`() {
        val url = "Zq9_-".repeat(9)
        assertEquals("sig=<b64>.", r("sig=$url=."))
        assertEquals("pk <b64>", r("pk ${"Ab1/".repeat(11)}=="))
    }

    @Test
    fun `a long hex run keeps the hex placeholder`() {
        assertEquals("sha=<hex>", r("sha=" + "ab".repeat(32)))
    }

    // ---- paths ----

    private val reportId = "0123456789abcdef0123456789abcdef"

    @Test
    fun `a relay URL keeps its port and route, its report id is redacted`() {
        assertEquals(
            "PUT https://relay.shake-document-protect.org:8443/api/v2/reports/<hex>/objects/3 failed",
            r("PUT https://relay.shake-document-protect.org:8443/api/v2/reports/$reportId/objects/3 failed"),
        )
    }

    @Test
    fun `an envelope path keeps its directories, its session id is redacted`() {
        assertEquals(
            "open /data/user/0/rs.readahead.washington.mobile/files/stream_envelopes/<hex>_c000001.fqe",
            r("open /data/user/0/rs.readahead.washington.mobile/files/stream_envelopes/${reportId}_c000001.fqe"),
        )
    }

    @Test
    fun `a key holding slashes is still redacted whole`() {
        // Standard base64 of random bytes: capitals, lowercase and digits all
        // along, so its slash-separated pieces do not read as names.
        assertEquals("pk <b64> set", r("pk q3Zt/9XkPw2Lm8aRb7Yc1Vd0Ns4Ue/6Hf5Gj3Ki2Ol1Mn set"))
        assertEquals("pk <b64> set", r("pk q3Zt/9XkPw2Lm8aRb7Yc1Vd0Ns4Ue6Hf5Gj3Ki2Ol1M= set"))
        // A path with a name in mixed case goes whole too.
        assertEquals("<b64>", r("Landroidx/work/impl/utils/futures/AbstractFuture"))
    }

    // ---- authorization ----

    @Test
    fun `an Authorization header loses its value`() {
        assertEquals("Authorization: <auth>", r("Authorization: Bearer abc.def.ghi"))
        assertEquals("hdr authorization:<auth>", r("hdr authorization:Basic dXNlcjpwYXNz"))
    }

    @Test
    fun `whatever follows Bearer is redacted, the lowercase word in prose is not`() {
        assertEquals("sending Bearer <auth>", r("sending Bearer tok3n with=more"))
        assertEquals("[OrphanSweep] no bearer this run", r("[OrphanSweep] no bearer this run"))
    }

    // ---- addresses ----

    @Test
    fun `IPv4 addresses are redacted, three-part versions are not`() {
        assertEquals("connect <ip>:8443", r("connect 192.168.1.20:8443"))
        assertEquals("route to <ip>.", r("route to 10.0.0.1."))
        assertEquals("version 2.12.0-test2 on 14.0.1", r("version 2.12.0-test2 on 14.0.1"))
    }

    @Test
    fun `IPv6 addresses are redacted, C++ scopes and clock times are not`() {
        assertEquals("peer <ip>%wlan0", r("peer fe80::1%wlan0"))
        assertEquals("peer <ip> up", r("peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up"))
        assertEquals("[<ip>]:8443", r("[::1]:8443"))
        assertEquals(
            "at android::MediaCodec::configure 12:34:56.789 Foo::class",
            r("at android::MediaCodec::configure 12:34:56.789 Foo::class"),
        )
    }

    @Test
    fun `e-mail addresses are redacted, object identities are not`() {
        assertEquals("mail <email> now", r("mail alice.b+x@example.org now"))
        assertEquals("cb=Foo@1a2b3c4 set", r("cb=Foo@1a2b3c4 set"))
    }

    // ---- recovery phrase ----

    @Test
    fun `three consecutive list words drop the line`() {
        assertNull(r("words: abaisser abandon abdiquer"))
        assertNull(r("ABAISSER Abandon abdiquer"))
        // Digits and punctuation between the words do not break the run.
        assertNull(r("1. abeille 2. abolir 3. abaisser"))
    }

    @Test
    fun `accents do not matter`() {
        assertNull(r("academie acquerir adequat"))
        assertNull(r("académie acquérir adéquat"))
    }

    @Test
    fun `two list words, or three with another word between, are kept`() {
        assertEquals("abaisser abandon encoder", r("abaisser abandon encoder"))
        assertEquals("abaisser x abandon y abdiquer", r("abaisser x abandon y abdiquer"))
    }

    @Test
    fun `the phrase check sees across lines`() {
        assertTrue(LogRedactor.mentionsPhrase("abaisser\nabandon\nabdiquer"))
        assertFalse(LogRedactor.mentionsPhrase("abaisser\nencoder\nabdiquer"))
    }

    @Test
    fun `ordinary words of the list count too, decomposed accents included`() {
        // "caméra", "image" and "surface" are all list words; the list file
        // stores the accent as a combining mark.
        assertNull(r("camera image surface"))
        assertNull(r("caméra image surface"))
    }

    // ---- what must survive ----

    @Test
    fun `diagnostic content survives unchanged`() {
        val lines = listOf(
            "Camera2CameraImpl{id=0} ERROR_CAMERA_IN_USE code=2 critical=false",
            "hevcEncoderInit mime=video/hevc component=c2.exynos.hevc.encoder bitrateRange=[1,100000000]",
            "hevcPreviewNegotiated w=1280 h=720 ratio=1.778",
            "app.git=a1b64cc build.sdk=34",
            "10-29 14:03:12.345  1234  5678 D CameraStateMachine: Recalculating open cameras",
            "build.fingerprint=samsung/a54xnsxx/a54x:14/UP1A.231005.007/A546BXXU7CXK1:user/release-keys",
            "\tat androidx.camera.camera2.internal.Camera2CameraImpl\$StateCallback.onError(Camera2CameraImpl.java:1234)",
        )
        for (line in lines) assertEquals(line, r(line))
    }
}
