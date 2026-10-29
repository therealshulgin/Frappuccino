package rs.readahead.washington.mobile.diagnostics

import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import rs.readahead.washington.mobile.service.StreamRecordingService
import rs.readahead.washington.mobile.util.jobs.UploadHttpClient

/**
 * The one request the diagnostics make: a gzip body POSTed to the test relay.
 *
 * Through [UploadHttpClient.instance] only, the client that carries the
 * relay's SPKI pins; a client built here would not have them. The request
 * carries no Authorization header and nothing derived from the witness's
 * identity, so that nothing in it names the identity that uploads reports.
 * The relay can still match the two by address and timing; the README says
 * so. What it does carry is the random install id and the app version, the
 * two headers the relay validates and keeps.
 */
internal object DiagnosticsHttp {

    const val PATH = "/diag/v1/logs"
    const val ENDPOINT = StreamRecordingService.DEFAULT_SERVER_URL + PATH

    private val GZIP = "application/gzip".toMediaType()

    fun request(body: ByteArray, installId: String, appVersion: String): Request =
        Request.Builder()
            .url(ENDPOINT)
            .header("X-Diag-Install", installId)
            .header("X-Diag-App", appVersion)
            .post(body.toRequestBody(GZIP))
            .build()

    /** The client every diagnostics request goes through: the pinned one. */
    val client: Call.Factory get() = UploadHttpClient.instance

    /** The HTTP status; an IOException when the relay could not be reached. */
    fun post(body: ByteArray, installId: String, appVersion: String): Int =
        client.newCall(request(body, installId, appVersion)).execute().use { it.code }
}
