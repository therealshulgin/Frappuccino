package rs.readahead.washington.mobile.data.sharedpref;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;


public class SharedPrefs {
    public static final String NONE = "";
    public static final String FEEDBACK_SHARING_ENBALED = "feedback_sharing_enabled";
    private static final String SHARED_PREFS_NAME = "washington_shared_prefs";

    // BT-HIGH-09 remediation (audit Red/Blue Team V2, 2026-04-17) — supprimé :
    //   * SECRET_PASSWORD ("secret_password")
    //   * PANIC_PASSWORD  ("panic_password")
    // Ces passwords étaient stockés en XML clair dans /data/data/.../shared_prefs/.
    // Le code Tella legacy qui les écrivait a été purgé, ces constantes étaient
    // dead code. Toute future re-introduction doit passer par PinProtectedStore.
    static final String PANIC_MESSAGE = "panic_message";
    static final String PANIC_GEOLOCATION = "panic_geolocation";
    static final String DELETE_SERVER_SETTINGS = "erase_everything";
    static final String ERASE_GALLERY = "erase_gallery";
    static final String FAILED_UNLOCK_OPTION = "failed_unlock_option";

    static final String SHOW_REMAINING_UNLOCK_ATTEMPTS = "show_remaining_unlock_attempts";

    static final String REMAINING_UNLOCK_ATTEMPTS = "remaining_unlock_attempts";
    static final String ERASE_FORMS = "erase_forms";
    private static final String LANGUAGE = "language";
    // BT-HIGH-09 — SECRET_MODE_ENABLED removed (dead code, was gating dead
    // password-based secret mode).
    static final String BYPASS_CENSORSHIP = "bypass_censorship";
    static final String ANONYMOUS_MODE = "anonymous_mode";
    static final String UNINSTALL_ON_PANIC = "uninstall_on_panic";
    static final String APP_FIRST_START = "app_first_start";
    static final String APP_ALIAS_NAME = "app_alias_name";
    static final String SUBMIT_CRASH_REPORTS = "submit_crash_reports";
    static final String ENABLE_CAMERA_PREVIEW = "enable_camera_preview";
    static final String LOCATION_ACCURACY_THRESHOLD = "location_threshold";
    static final String OFFLINE_MODE = "offline_mode";
    static final String QUICK_EXIT_BUTTON = "quick_exit_button";
    static final String COLLECT_OPTION = "collect_option";
    static final String INSTALLATION_ID = "installation_id";
    static final String LAST_COLLECT_REFRESH = "last_collect_refresh";
    static final String VIDEO_RESOLUTION = "video_resolution";
    static final String AUTO_UPLOAD_SERVER = "auto_upload_server";
    static final String AUTO_UPLOAD = "auto_upload";
    static final String AUTO_DELETE = "auto_delete";
    static final String METADATA_AUTO_UPLOAD = "metadata_auto_upload";
    static final String AUTO_UPLOAD_PAUSED = "auto_upload_paused";
    static final String LOCK_TIMEOUT = "lock_timeout";
    static final String RATCHET_AUTOLOCK_MS = "ratchet_autolock_ms";
    static final String OEM_GUIDE_SHOWN = "oem_guide_shown";
    static final String LAST_SEEN_KILL_MS = "last_seen_kill_ms";
    static final String MUTE_CAMERA_SHUTTER = "mute_camera_shutter";
    static final String KEEP_EXIF = "keep_exif";
    static final String SET_SECURITY_SCREEN = "set_security_screen";
    static final String SHOW_FAVORITE_FORMS = "show_favorite_forms";
    static final String SHOW_FAVORITE_TEMPLATES = "show_favorite_Templates";
    static final String SHOW_RECENT_FILES = "show_recent_files";
    static final String UPGRADE_TELLA_2 = "update_tella_2";
    static final String SHOW_IMPROVEMENT_SECTION = "show_improvement_section";
    static final String HAS_IMPROVEMENT_ACCEPTED = "has_improvement_accepted";
    static final String TIME_IMPROVEMENT_ACCEPTED = "time_improvement_accepted";
    static final String TEMP_TIMEOUT = "temp_timeout";
    static final String EXIT_TIMEOUT = "exit_timeout";
    static final String JAVAROSA_3_UPGRADE = "javarosa_3_upgrade";
    static final String TEXT_JUSTIFICATION = "text_justification";
    static final String TEXT_SPACING = "text_spacing";
    static final String SHOW_UPDATE_MIGRATION_BOTTOM_SHEET = "SHOW_UPDATE_MIGRATION_BOTTOM_SHEET";
    static final String SHOW_MIGRATION_FAILED_BOTTOM_SHEET = "show_migration_failed_bottom_sheet";
    static final String IS_MIGRATED_MAIN_DB = "is_migrated_main_db";
    static final String IS_FRESH_INSTALL = "is_fresh_install";

    private static SharedPrefs instance;
    private SharedPreferences pref;
    private SharedPreferences.Editor editor;


    public static SharedPrefs getInstance() {
        synchronized (SharedPrefs.class) {
            if (instance == null) {
                instance = new SharedPrefs();
            }

            return instance;
        }
    }

    public SharedPreferences getPref() {
        return pref;
    }

    @SuppressLint("CommitPrefEdits")
    public void init(Context context) {
        pref = context.getSharedPreferences(SHARED_PREFS_NAME, Context.MODE_PRIVATE);
        editor = pref.edit();
    }

    // BT-HIGH-09 — setPanicPassword / getPanicPassword supprimés (dead code,
    // cleartext plaintext en XML).

    /*public boolean isTorModeActive() {
        return pref.getBoolean(TOR_MODE_ENABLED, false);
    }

    public void setToreModeActive(boolean activated) {
        editor.putBoolean(TOR_MODE_ENABLED, activated);
        editor.apply();
    }*/

    /*public boolean askForTorOnStart() {
        return pref.getBoolean(ASK_FOR_TOR, true);
    }

    public void setAskForTorOnStart(boolean activated) {
        editor.putBoolean(ASK_FOR_TOR, activated);
        editor.apply();
    }*/

    public boolean isEraseGalleryActive() {
        return pref.getBoolean(ERASE_GALLERY, false);
    }

    public void setEraseGalleryActive(boolean activated) {
        editor.putBoolean(ERASE_GALLERY, activated);
        editor.apply();
    }

    public void setAppLanguage(String language) {
        editor.putString(LANGUAGE, language);
        editor.apply();
    }

    public String getAppLanguage() {
        return pref.getString(LANGUAGE, null);
    }

    boolean getBoolean(final String name, final boolean def) {
        return pref.getBoolean(name, def);
    }

    boolean setBoolean(final String name, final boolean value) {
        editor.putBoolean(name, value);
        editor.apply();
        return value;
    }

    @NonNull
    String getString(@NonNull final String name, final String def) {
        String str = pref.getString(name, def);
        return str != null ? str : NONE;
    }

    void setString(@NonNull final String name, final String value) {
        editor.putString(name, value);
        editor.apply();
    }

    float getFloat(final String name, final float def) {
        return pref.getFloat(name, def);
    }

    float setFloat(final String name, final float value) {
        editor.putFloat(name, value);
        editor.apply();
        return value;
    }

    long getLong(final String name, final long def) {
        return pref.getLong(name, def);
    }

    long setLong(final String name, final long value) {
        editor.putLong(name, value);
        editor.apply();
        return value;
    }

    private SharedPrefs() {
    }
}
