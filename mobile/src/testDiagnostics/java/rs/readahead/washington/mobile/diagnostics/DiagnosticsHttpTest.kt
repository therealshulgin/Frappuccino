package rs.readahead.washington.mobile.diagnostics

import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test
import rs.readahead.washington.mobile.util.jobs.UploadHttpClient

class DiagnosticsHttpTest {

    @Test
    fun `the request goes to the test relay's diagnostics route, with the two headers and nothing else of ours`() {
        val body = byteArrayOf(0x1f, 0x8b.toByte(), 8, 0)
        val r = DiagnosticsHttp.request(body, "0".repeat(32), "2.12.0-test2")
        assertEquals("POST", r.method)
        assertEquals("https://relay.shake-document-protect.org:8443/diag/v1/logs", r.url.toString())
        assertEquals(setOf("X-Diag-Install", "X-Diag-App"), r.headers.names())
        assertEquals("0".repeat(32), r.header("X-Diag-Install"))
        assertEquals("2.12.0-test2", r.header("X-Diag-App"))
        assertNull(r.header("Authorization"))
        assertEquals("application/gzip", r.body!!.contentType().toString())
        val sent = Buffer().also { r.body!!.writeTo(it) }.readByteArray()
        assertEquals(body.toList(), sent.toList())
    }

    @Test
    fun `it goes through the pinned client`() {
        assertSame(UploadHttpClient.instance, DiagnosticsHttp.client)
    }
}
