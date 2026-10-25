package org.stream.crypto.upload

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import org.stream.crypto.SecureWipe
import timber.log.Timber
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

/**
 * Keeps the queue key: the 32 bytes under which every envelope's trailer is
 * sealed (report address, signatures, object name).
 *
 * The key is created at enrollment or at the legacy migration, stored in an
 * [EncryptedFile] wrapped by the app's Android Keystore master key (the same
 * protection level as the encrypted preferences), and installed into the Rust
 * process-global holder at process start, by the application and by any worker
 * that runs first. Rust never gets it from anywhere else and never writes it.
 *
 * This class only handles the key as a [ByteArray], never a String (Base64,
 * hex, a log line), and wipes that array after use. Copies outside its
 * control are not wiped: the plaintext segment buffers inside the
 * [EncryptedFile] streams, and the buffers UniFFI uses to carry the key into
 * Rust (the key returned by `queueKeyGenerate`, the argument of
 * `queueKeyInstall`), stay in memory until they are reused. In a process that
 * keeps running after an emergency wipe, only a reader of its live memory can
 * reach them. What the Keystore protects is the file at rest: an extraction
 * that can use this app's Keystore reads the key, and with it the report
 * addresses of the envelopes still queued (documented residual). [wipe]
 * overwrites and deletes the file; on flash that is best effort, and the
 * [EncryptedFile] keyset and the Keystore master key, shared with the encrypted
 * preferences, are not deleted with it.
 *
 * Without an installed key no envelope can be written, read or sent. The Rust
 * calls say so explicitly and leave every file where it is, so a missing key
 * stops the queue, never empties it.
 */
object QueueKeyStore {

    private const val FILE_NAME = "stream_queue_key.bin"
    private const val KEY_LEN = 32

    private fun keyFile(context: Context): File =
        File(context.applicationContext.filesDir, FILE_NAME)

    fun exists(context: Context): Boolean = keyFile(context).exists()

    /**
     * Install the stored key if it is not installed yet. Never creates one.
     * Returns whether a key is installed when it returns. Cheap once installed.
     */
    @Synchronized
    fun ensureInstalled(context: Context): Boolean {
        if (uniffi.frappuccino.queueKeyPresent()) return true
        val file = keyFile(context)
        if (!file.exists()) return false
        val key = try {
            read(context, file)
        } catch (e: Exception) {
            Timber.e(e, "QueueKeyStore: stored queue key unreadable")
            return false
        }
        return try {
            uniffi.frappuccino.queueKeyInstall(key)
            true
        } catch (e: Exception) {
            Timber.e(e, "QueueKeyStore: queue key install failed")
            false
        } finally {
            SecureWipe.wipe(key)
        }
    }

    /**
     * Make sure a key exists and is installed, creating it if there is none
     * (enrollment, migration). Throws if that cannot be done: the caller treats
     * it as fatal, because a device that can produce no envelope cannot record.
     *
     * A stored key that cannot be read is replaced only when [replaceUnreadable]
     * is true. At enrollment that is a fresh start; at the migration it is
     * allowed only while no envelope exists, since replacing the key makes
     * every envelope sealed under the old one unreadable.
     */
    @Synchronized
    fun createOrInstall(context: Context, replaceUnreadable: Boolean) {
        val file = keyFile(context)
        if (file.exists()) {
            val stored = try {
                read(context, file)
            } catch (e: Exception) {
                if (!replaceUnreadable) throw IOException("stored queue key unreadable", e)
                Timber.w(e, "QueueKeyStore: unreadable queue key replaced")
                null
            }
            if (stored != null) {
                try {
                    uniffi.frappuccino.queueKeyInstall(stored)
                } finally {
                    SecureWipe.wipe(stored)
                }
                return
            }
            deleteFile(file)
        }
        val fresh = uniffi.frappuccino.queueKeyGenerate()
        try {
            write(context, file, fresh)
            val back = read(context, file)
            try {
                if (!MessageDigest.isEqual(back, fresh)) throw IOException("queue key read-back mismatch")
            } finally {
                SecureWipe.wipe(back)
            }
            // Installed only once it is known to be stored: an envelope sealed
            // under a key that was never stored would be unreadable after the
            // next restart.
            uniffi.frappuccino.queueKeyInstall(fresh)
        } catch (e: Exception) {
            deleteFile(file)
            throw e
        } finally {
            SecureWipe.wipe(fresh)
        }
    }

    /** Emergency wipe: drop the installed key and delete the stored one. */
    @Synchronized
    fun wipe(context: Context) {
        try {
            uniffi.frappuccino.queueKeyClear()
        } catch (e: Exception) {
            Timber.w(e, "QueueKeyStore: queueKeyClear failed")
        }
        deleteFile(keyFile(context))
    }

    private fun encryptedFile(context: Context, file: File): EncryptedFile {
        val masterKey = MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        // The file name is bound into the encryption: the file cannot be
        // written under a temporary name and renamed into place.
        return EncryptedFile.Builder(
            context.applicationContext,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()
    }

    private fun read(context: Context, file: File): ByteArray {
        val out = ByteArray(KEY_LEN)
        try {
            encryptedFile(context, file).openFileInput().use { input ->
                readFully(input, out)
                if (input.read() != -1) throw IOException("queue key file longer than a key")
            }
        } catch (e: Exception) {
            SecureWipe.wipe(out)
            throw e
        }
        return out
    }

    private fun readFully(input: InputStream, out: ByteArray) {
        var off = 0
        while (off < out.size) {
            val n = input.read(out, off, out.size - off)
            if (n < 0) throw IOException("queue key file shorter than a key")
            off += n
        }
    }

    private fun write(context: Context, file: File, key: ByteArray) {
        require(key.size == KEY_LEN) { "a queue key is $KEY_LEN bytes" }
        encryptedFile(context, file).openFileOutput().use { out ->
            out.write(key)
            out.flush()
        }
        // Push the file and its directory entry to storage: a key lost to a
        // power cut after envelopes were sealed under it would make them
        // unreadable for good.
        try {
            java.io.FileOutputStream(file, true).use { it.fd.sync() }
        } catch (e: Exception) {
            Timber.w(e, "QueueKeyStore: fsync of the key file failed")
        }
        EnvelopeQueue.fsyncDir(file.parentFile ?: return)
    }

    private fun deleteFile(file: File) {
        if (file.exists()) EnvelopeQueue.secureDelete(file)
    }
}
