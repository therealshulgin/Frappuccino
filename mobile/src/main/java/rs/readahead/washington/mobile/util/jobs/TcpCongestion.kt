package rs.readahead.washington.mobile.util.jobs

import timber.log.Timber

/**
 * Fail-safe wrapper over `libtcpcc.so` for reading / setting a socket's TCP
 * congestion control (transport plan — `docs/TRANSPORT_PLAN.md`).
 *
 * A whole JNI library ships for these two calls because TCP_CONGESTION is a
 * *string* socket option. Neither `android.system.Os` (no string get/setsockopt)
 * nor procfs (SELinux denies `untrusted_app` reading
 * `/proc/sys/net/ipv4/tcp_congestion_control`, verified on the Seeker) expose it
 * to an app. A socket-level get/setsockopt IS permitted in the app domain, hence
 * the small `tcpcc.c`. Dropping the `.so` in favour of a procfs read buys a
 * silent SELinux denial, which the guards below degrade to "unknown" — so the
 * regression would not show up in test either.
 *
 * If `libtcpcc.so` is missing (jniLibs is gitignored — run
 * `mobile/src/main/cpp/build-tcpcc.sh`) or any native call throws, every method
 * degrades gracefully ("unknown" / "skipped"). That path carries a fresh clone,
 * which has no `.so` at all, and is why the app still works there. Nothing here
 * can crash the app or break an upload — setting TCP_CONGESTION never tears
 * down a connection.
 */
object TcpCongestion {

    private val loaded: Boolean = try {
        System.loadLibrary("tcpcc")
        true
    } catch (e: Throwable) {
        Timber.tag("StreamMetrics").w("tcpcc native lib not loaded: %s", e.javaClass.simpleName)
        false
    }

    private external fun nativeProbe(): String
    private external fun nativeApplyBbr(fd: Int): String

    /**
     * Self-contained probe (touches no upload socket — opens its own throwaway
     * socket). Returns e.g. "default=cubic;bbr=unavailable" or
     * "default=cubic;bbr=ok", or "unknown" if the native lib isn't loaded.
     */
    fun probe(): String =
        if (!loaded) {
            "unknown"
        } else {
            try {
                nativeProbe()
            } catch (e: Throwable) {
                "unknown"
            }
        }

    /**
     * Phase 0a-2 — best-effort switch of a connected [socket] to bbr. Returns
     * the CC actually in effect afterwards ("bbr" / "cubic" / ...), or
     * "skipped" if the lib isn't loaded or the fd couldn't be resolved. Never
     * throws, never breaks the connection.
     */
    fun applyBbrToSocket(socket: java.net.Socket): String {
        if (!loaded) return "skipped"
        val fd = socketFd(socket)
        if (fd < 0) return "skipped"
        return try {
            nativeApplyBbr(fd)
        } catch (e: Throwable) {
            "error"
        }
    }

    /**
     * Resolve the raw int fd behind a [java.net.Socket] via reflection on
     * platform-private fields (`Socket.impl` -> `SocketImpl.getFileDescriptor`
     * -> `FileDescriptor`). These may be blocked by hidden-API on newer
     * Android; on any failure we return -1 and the caller no-ops (keeps the
     * default CC). Only used by the gated Phase 0a-2 stopgap.
     */
    private fun socketFd(socket: java.net.Socket): Int {
        return try {
            val implField = java.net.Socket::class.java.getDeclaredField("impl")
            implField.isAccessible = true
            val impl = implField.get(socket) as java.net.SocketImpl
            val getFd = java.net.SocketImpl::class.java
                .getDeclaredMethod("getFileDescriptor")
            getFd.isAccessible = true
            val fileDesc = getFd.invoke(impl) as java.io.FileDescriptor
            fdToInt(fileDesc)
        } catch (e: Throwable) {
            -1
        }
    }

    private fun fdToInt(fd: java.io.FileDescriptor): Int {
        // Preferred: Android's hidden FileDescriptor.getInt$().
        try {
            val m = java.io.FileDescriptor::class.java.getDeclaredMethod("getInt\$")
            m.isAccessible = true
            return m.invoke(fd) as Int
        } catch (e: Throwable) {
            // Fallback: the private `descriptor` int field.
            return try {
                val f = java.io.FileDescriptor::class.java.getDeclaredField("descriptor")
                f.isAccessible = true
                f.getInt(fd)
            } catch (e2: Throwable) {
                -1
            }
        }
    }
}
