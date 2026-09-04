package rs.readahead.washington.mobile.util.jobs

import timber.log.Timber
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import javax.net.SocketFactory

/**
 * OkHttp [SocketFactory] that best-effort switches a TCP socket to bbr right
 * after connect, when [BbrStopgap.enabled]. A measurement expedient, not a
 * production tuning knob: transport stopgap, `docs/TRANSPORT_PLAN.md`
 * (Phase 0a-2).
 *
 * The only thing this factory may ever add is a post-connect
 * setsockopt(TCP_CONGESTION), applied after `super.connect` returns: it never
 * changes how the socket connects, so an upload cannot break here. On any
 * failure (bbr unavailable, fd not resolvable, hidden-API blocked) the socket
 * simply keeps its default CC (cubic). No-op on devices without bbr (the
 * Seeker). It is installed **only in debug builds** ([UploadHttpClient]), so
 * release uploads use the platform default factory and are completely
 * unaffected.
 *
 * Scope: chunk PUTs no longer go through OkHttp — they go through the Rust
 * transport (`uniffi.frappuccino.uploadPutReportChunk`, DIRECT_TLS / OBF_QUIC),
 * so this factory no longer sees the testimony-upload sockets at all. What is
 * left on the shared [UploadHttpClient] is the relay `/health` probe and the
 * opt-in provenance timestamp call; the `bbrApply` lines you still see come
 * from those, not from an upload connection. That client multiplexes over a
 * single HTTP/2 connection, so a session emits ~1 `bbrApply` metrics line, not
 * one per call — a count of 1 is not a sign that the factory misfired.
 */
class BbrSocketFactory : SocketFactory() {

    override fun createSocket(): Socket = BbrSocket()

    override fun createSocket(host: String?, port: Int): Socket =
        BbrSocket().apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(
        host: String?, port: Int, localHost: InetAddress?, localPort: Int,
    ): Socket = BbrSocket().apply {
        bind(InetSocketAddress(localHost, localPort))
        connect(InetSocketAddress(host, port))
    }

    override fun createSocket(host: InetAddress?, port: Int): Socket =
        BbrSocket().apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(
        host: InetAddress?, port: Int, localHost: InetAddress?, localPort: Int,
    ): Socket = BbrSocket().apply {
        bind(InetSocketAddress(localHost, localPort))
        connect(InetSocketAddress(host, port))
    }

    private class BbrSocket : Socket() {
        override fun connect(endpoint: SocketAddress?, timeout: Int) {
            super.connect(endpoint, timeout)
            maybeApplyBbr()
        }

        override fun connect(endpoint: SocketAddress?) {
            super.connect(endpoint)
            maybeApplyBbr()
        }

        private fun maybeApplyBbr() {
            if (!BbrStopgap.enabled) return
            try {
                val cc = TcpCongestion.applyBbrToSocket(this)
                Timber.tag("StreamMetrics").i("bbrApply cc=%s", cc)
            } catch (e: Throwable) {
                // Best-effort only — never affect the connection.
            }
        }
    }
}
