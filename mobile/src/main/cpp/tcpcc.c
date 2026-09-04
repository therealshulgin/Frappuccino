/*
 * Why this is native rather than Kotlin: the congestion control of a socket is
 * the string option TCP_CONGESTION, which neither android.system.Os (no string
 * get/setsockopt) nor procfs (SELinux denies untrusted_app reading
 * /proc/sys/net/ipv4/tcp_congestion_control) expose to an app. A socket-level
 * getsockopt/setsockopt IS permitted to the untrusted_app domain, so this small
 * JNI shim is the only way to (a) read the CC our upload sockets actually ride
 * and (b) try to switch them to bbr where available. It serves the Phase 0a
 * transport stopgap (docs/TRANSPORT_PLAN.md).
 *
 * Builds to libtcpcc.so via mobile/src/main/cpp/build-tcpcc.sh. The .so lives
 * (gitignored) in mobile/src/main/jniLibs/<abi>/ like libuniffi_frappuccino.so;
 * loading is fail-safe on the Kotlin side, so a missing/denied lib just means
 * "cc unknown / bbr not applied", never a crash.
 */
#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifndef TCP_CONGESTION
#define TCP_CONGESTION 13
#endif

/* Read the active congestion control of fd into buf (NUL-terminated). */
static int read_cc(int fd, char *buf, socklen_t buflen) {
    memset(buf, 0, buflen);
    socklen_t len = buflen - 1;
    return getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, &len);
}

/*
 * nativeProbe — self-contained, touches NO upload socket. Opens a throwaway
 * TCP socket, reads its default CC, tries to set bbr, reads back, closes.
 * Returns "default=<cc>;bbr=<ok|unavailable|error>". Never throws.
 */
JNIEXPORT jstring JNICALL
Java_rs_readahead_washington_mobile_util_jobs_TcpCongestion_nativeProbe(
        JNIEnv *env, jobject thiz) {
    (void) thiz;
    char out[128];
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return (*env)->NewStringUTF(env, "default=unknown;bbr=error");
    }
    char def[32];
    if (read_cc(fd, def, sizeof(def)) != 0) {
        snprintf(def, sizeof(def), "unknown");
    }
    const char *bbr = "unavailable";
    if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "bbr", 3) == 0) {
        char now[32];
        if (read_cc(fd, now, sizeof(now)) == 0 && strcmp(now, "bbr") == 0) {
            bbr = "ok";
        } else {
            bbr = "error";
        }
    }
    close(fd);
    snprintf(out, sizeof(out), "default=%s;bbr=%s", def, bbr);
    return (*env)->NewStringUTF(env, out);
}

/*
 * nativeApplyBbr — best-effort switch of an EXISTING (typically connected)
 * socket fd to bbr, then read back. Returns the CC actually in effect after
 * the attempt ("bbr" if it took, "cubic"/other if bbr is unavailable, or
 * "error" on a bad fd). Setting TCP_CONGESTION never tears down the
 * connection, so on any failure the socket keeps whatever CC it had.
 */
JNIEXPORT jstring JNICALL
Java_rs_readahead_washington_mobile_util_jobs_TcpCongestion_nativeApplyBbr(
        JNIEnv *env, jobject thiz, jint fd) {
    (void) thiz;
    if (fd < 0) {
        return (*env)->NewStringUTF(env, "error");
    }
    /* Ignore the result: if bbr is unavailable this fails with ENOENT and the
     * socket keeps its current CC; we report whatever read-back shows. */
    setsockopt((int) fd, IPPROTO_TCP, TCP_CONGESTION, "bbr", 3);
    char now[32];
    if (read_cc((int) fd, now, sizeof(now)) != 0) {
        return (*env)->NewStringUTF(env, "error");
    }
    return (*env)->NewStringUTF(env, now);
}
