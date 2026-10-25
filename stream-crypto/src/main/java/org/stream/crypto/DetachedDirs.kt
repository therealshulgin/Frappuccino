package org.stream.crypto

import java.io.File

/**
 * Directories another part of the app has already renamed out of reach for
 * the emergency wipe, handed to `StreamUploadManager.panicWipe` so they are
 * erased in its single background pass, in its order: every [plaintext]
 * directory (from any part of the app) before any [ciphertext] one.
 *
 * [afterErase] runs on that same background thread once the pass is done:
 * the place for a second pass over directories a write in flight may still
 * have reached, or for what lives outside the app's directories.
 */
data class DetachedDirs(
    val plaintext: List<File> = emptyList(),
    val ciphertext: List<File> = emptyList(),
    val afterErase: () -> Unit = {},
)
