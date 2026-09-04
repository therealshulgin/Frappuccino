package rs.readahead.washington.mobile.views.activity

import android.content.Context
import android.content.SharedPreferences

/**
 * PinAttemptTracker — compteur d'échecs PIN persistant pour [PinUnlockActivity].
 *
 * `attempts` et `lockUntilMs` doivent rester écrits sur disque de façon
 * SYNCHRONE, via `SharedPreferences.commit()`. Ne pas les remplacer par
 * `apply()`, ni les ramener en champs d'instance sur l'activity : c'est ainsi
 * qu'ils vivaient avant, et un attaquant qui force-killait l'app entre deux
 * essais — via les settings, le task manager, ou `adb shell am kill` —
 * relançait avec un compteur à 0. Le backoff exponentiel devenait inopérant et
 * le PIN 6 chiffres brute-forçable sans limite (10⁶ possibles, ~11 jours à 1s
 * de dérivation Argon2id, ~15 min si les paramètres Argon2id sont baissés, ce
 * dernier chiffre étant aussi la raison de ne pas les baisser pour gagner en
 * réactivité d'UI). Persistés en XML, les deux valeurs survivent au force-kill
 * comme au reboot (remédiation BT-HIGH-15, audit Red/Blue Team V2,
 * 2026-04-17).
 *
 * Elles ne passent pas par PinProtectedStore, et n'ont pas à y passer : un
 * entier et un timestamp de backoff ne sont pas des données sensibles, le
 * stockage plaintext est acceptable ici (obfuscation R8 + FLAG_SECURE
 * complètent).
 */
object PinAttemptTracker {

    private const val PREFS_NAME = "pin_attempt_tracker"
    private const val KEY_ATTEMPTS = "pin_attempts"
    private const val KEY_LOCK_UNTIL = "pin_lock_until_ms"

    /**
     * Schedule de backoff exponentiel. Index = nombre d'échecs cumulés.
     * Le palier haut de 10 min est atteint dès le 8ème échec et s'applique
     * ensuite à tous les échecs suivants, l'index étant clampé à `size - 1`.
     */
    private val DELAY_MS_SCHEDULE = longArrayOf(
        0L,        // 0 échec
        0L,        // 1er échec
        0L,        // 2e
        5_000L,    // 3e  : 5s
        15_000L,   // 4e  : 15s
        60_000L,   // 5e  : 1min
        120_000L,  // 6e  : 2min
        300_000L,  // 7e  : 5min
        600_000L,  // 8e  : 10min
        600_000L   // 9e+ : clamped 10min
    )

    fun getAttempts(ctx: Context): Int =
        prefs(ctx).getInt(KEY_ATTEMPTS, 0)

    fun getLockUntilMs(ctx: Context): Long =
        prefs(ctx).getLong(KEY_LOCK_UNTIL, 0L)

    /**
     * Enregistre un échec. Incrémente le compteur, calcule le backoff,
     * écrit synchronement via `commit()`.
     *
     * @return le timestamp jusqu'auquel l'UI doit refuser de nouvelles
     *   tentatives (0 si pas de backoff actif).
     */
    fun recordFailure(ctx: Context): Long {
        val p = prefs(ctx)
        val attempts = p.getInt(KEY_ATTEMPTS, 0) + 1
        val penaltyIdx = minOf(attempts, DELAY_MS_SCHEDULE.size - 1)
        val penalty = DELAY_MS_SCHEDULE[penaltyIdx]
        val lockUntil = if (penalty > 0) System.currentTimeMillis() + penalty else 0L
        p.edit()
            .putInt(KEY_ATTEMPTS, attempts)
            .putLong(KEY_LOCK_UNTIL, lockUntil)
            .commit()
        return lockUntil
    }

    /** Enregistre un succès : efface le compteur et le lockout. Commit synchrone. */
    fun recordSuccess(ctx: Context) {
        prefs(ctx).edit()
            .remove(KEY_ATTEMPTS)
            .remove(KEY_LOCK_UNTIL)
            .commit()
    }

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
}
