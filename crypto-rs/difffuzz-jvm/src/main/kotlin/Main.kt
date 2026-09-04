/*
 * Kotlin<->Rust differential-fuzz harness — ROADMAP 8.4 item 3.
 *
 * Reads the JSONL corpus emitted by `frappuccino-difffuzz-dump` (each line:
 * {api, args:[hex], outcome}) and replays every case through the generated
 * UniFFI bindings (Kotlin -> JNA -> the same Rust fn the dumper called
 * directly). Each replay outcome is canonicalised to a string and compared to
 * the recorded Rust outcome:
 *   - equal            -> the marshalling preserved the result;
 *   - different        -> a Kotlin<->Rust glue (marshalling) bug;
 *   - unexpected throw  -> a non-FfiException escaped the binding (glue bug);
 *   - JVM dies, no summary -> an uncaught Rust panic crossed the boundary.
 *
 * Run: ../gradlew -p . run --args="<corpus.jsonl>"
 * (jna.library.path is wired to ../target/debug in build.gradle.kts.)
 */

import org.json.JSONObject
import uniffi.frappuccino.ArchiveIdentity
import uniffi.frappuccino.EphemeralRatchet
import uniffi.frappuccino.FfiException
import uniffi.frappuccino.StreamIdentity
import uniffi.frappuccino.bip39ValidateFr
import uniffi.frappuccino.pinStoreOpen
import java.io.File

private fun hexToBytes(s: String): ByteArray =
    ByteArray(s.length / 2) { i ->
        ((s[i * 2].digitToInt(16) shl 4) or s[i * 2 + 1].digitToInt(16)).toByte()
    }

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

/** Stable (variant, detail) projection mirroring the Rust dumper's `err_repr`. */
private fun reprErr(e: FfiException): String {
    val (variant, detail) = when (e) {
        is FfiException.InvalidMnemonicWord -> "InvalidMnemonicWord" to "${e.word}|${e.language}"
        is FfiException.InvalidMnemonic -> "InvalidMnemonic" to e.detail
        is FfiException.DerivationFailed -> "DerivationFailed" to e.detail
        is FfiException.EmptyInput -> "EmptyInput" to ""
        is FfiException.AlreadyConsumed -> "AlreadyConsumed" to e.resource
        is FfiException.InvalidSignature -> "InvalidSignature" to ""
        is FfiException.WrongPin -> "WrongPin" to ""
        is FfiException.InvalidBlob -> "InvalidBlob" to e.detail
        is FfiException.Network -> "Network" to e.detail
        is FfiException.Internal -> "Internal" to e.detail
        is FfiException.Io -> "Io" to e.detail
    }
    return "err:$variant:$detail"
}

/** Canonical string of the RECORDED Rust outcome (the corpus `outcome` object). */
private fun expectedCanon(o: JSONObject): String = when (val tag = o.getString("tag")) {
    "ok_void" -> "ok_void"
    "ok_bytes" -> "ok_bytes:${o.getString("value")}"
    "ok_str" -> "ok_str:${o.getString("value")}"
    "err" -> "err:${o.getString("variant")}:${o.getString("detail")}"
    else -> "unknown_tag:$tag"
}

/**
 * Replay one case through the UniFFI bindings, returning the canonical outcome
 * string. FfiException is the expected error channel; any other Throwable is a
 * glue anomaly surfaced with the `throw:` prefix (never equal to a Rust line).
 */
private fun replay(api: String, args: List<ByteArray>): String =
    try {
        when (api) {
            "bip39_validate_fr" -> {
                bip39ValidateFr(args[0]); "ok_void"
            }
            "identity_fingerprint" ->
                StreamIdentity.fromPublicKeys(args[0], args[1]).use { id ->
                    "ok_str:${id.readableFingerprint()}"
                }
            "ratchet_deserialize_serialize" ->
                EphemeralRatchet.deserialize(args[0]).use { r ->
                    "ok_bytes:${r.serialize().toHex()}"
                }
            "pin_store_open" -> "ok_bytes:${pinStoreOpen(args[0], args[1]).toHex()}"
            "archive_from_mnemonic" ->
                ArchiveIdentity.fromMnemonic(args[0], args[1]).use { a ->
                    a.identity().use { id -> "ok_str:${id.ed25519PkHex()}" }
                }
            else -> "unknown_api:$api"
        }
    } catch (e: FfiException) {
        reprErr(e)
    } catch (e: Throwable) {
        "throw:${e::class.simpleName}:${e.message}"
    }

fun main(argv: Array<String>) {
    if (argv.isEmpty()) {
        System.err.println("usage: difffuzz-jvm <corpus.jsonl>")
        kotlin.system.exitProcess(2)
    }
    val corpus = File(argv[0])
    require(corpus.isFile) { "corpus not found: ${corpus.absolutePath}" }

    var total = 0
    var matched = 0
    val mismatches = mutableListOf<String>()
    val perApi = sortedMapOf<String, IntArray>() // api -> [total, matched]

    corpus.forEachLine { line ->
        if (line.isBlank()) return@forEachLine
        val obj = JSONObject(line)
        val api = obj.getString("api")
        val args = obj.getJSONArray("args").let { arr ->
            (0 until arr.length()).map { hexToBytes(arr.getString(it)) }
        }
        val expected = expectedCanon(obj.getJSONObject("outcome"))
        val actual = replay(api, args)

        total++
        val stat = perApi.getOrPut(api) { IntArray(2) }
        stat[0]++
        if (actual == expected) {
            matched++
            stat[1]++
        } else if (mismatches.size < 40) {
            mismatches += buildString {
                append("api=").append(api)
                append(" args=").append(obj.getJSONArray("args"))
                append("\n   expected: ").append(expected)
                append("\n   actual:   ").append(actual)
            }
        }
    }

    println("=== Kotlin<->Rust differential-fuzz ===")
    println("corpus: ${corpus.absolutePath}")
    for ((api, s) in perApi) {
        println("  %-32s %5d / %-5d %s".format(api, s[1], s[0], if (s[1] == s[0]) "OK" else "<<< MISMATCH"))
    }
    println("total: $matched / $total matched")
    if (mismatches.isNotEmpty()) {
        println("\n--- first ${mismatches.size} mismatches ---")
        mismatches.forEach { println(it) }
    }
    kotlin.system.exitProcess(if (matched == total) 0 else 1)
}
