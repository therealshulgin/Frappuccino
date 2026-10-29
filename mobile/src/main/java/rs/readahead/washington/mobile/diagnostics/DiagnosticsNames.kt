package rs.readahead.washington.mobile.diagnostics

/**
 * The names a pre-release test build gives to what its diagnostics leave on
 * the phone. Both diagnostics source sets use them: the test build to write
 * and erase, a production build to remove what a test build installed before
 * it left behind (its [Diagnostics] facade does nothing else).
 */
internal object DiagnosticsNames {
    /** Under `filesDir`: the redacted log lines waiting to be sent. */
    const val DIR = "diag"

    /** SharedPreferences file holding the random install id, nothing else. */
    const val PREFS = "frappuccino_diag"

    /** Unique one-time upload work. */
    const val UPLOAD_WORK = "frappuccino-diag-upload"

    /** Unique periodic upload work. */
    const val PERIODIC_WORK = "frappuccino-diag-upload-periodic"
}
