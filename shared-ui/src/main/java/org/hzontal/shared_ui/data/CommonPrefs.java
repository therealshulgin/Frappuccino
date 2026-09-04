package org.hzontal.shared_ui.data;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;

import timber.log.Timber;


public class CommonPrefs {
    public static final String NONE = "";
    private static final String SHARED_PREFERENCES_NAME = "tella_shared_preferences";

    static final String SHOW_IMPROVEMENT_SECTION = "show_improvement_section";
    static final String HAS_IMPROVEMENT_ACCEPTED = "has_improvement_accepted";
    static final String TIME_IMPROVEMENT_ACCEPTED = "time_improvement_accepted";

    private static CommonPrefs instance;
    private SharedPreferences commonPref;
    private SharedPreferences.Editor commonEditor;


    public static CommonPrefs getInstance() {
        synchronized (CommonPrefs.class) {
            if (instance == null) {
                instance = new CommonPrefs();
            }

            return instance;
        }
    }

    public SharedPreferences getPref() {
        return commonPref;
    }

    @SuppressLint("CommitPrefEdits")
    public void init(Context context) {
        commonPref = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        commonEditor = commonPref.edit();
    }

    boolean getBoolean(final String name, final boolean def) {
        return commonPref.getBoolean(name, def);
    }

    boolean setBoolean(final String name, final boolean value) {
        commonEditor.putBoolean(name, value);
        commonEditor.apply();
        return value;
    }

    @NonNull
    String getString(@NonNull final String name, final String def) {
        String str = commonPref.getString(name, def);
        return str != null ? str : NONE;
    }

    void setString(@NonNull final String name, final String value) {
        commonEditor.putString(name, value);
        commonEditor.apply();
    }

    float getFloat(final String name, final float def) {
        return commonPref.getFloat(name, def);
    }

    float setFloat(final String name, final float value) {
        commonEditor.putFloat(name, value);
        commonEditor.apply();
        return value;
    }

    long getLong(final String name, final long def) {
        return commonPref.getLong(name, def);
    }

    long setLong(final String name, final long value) {
        commonEditor.putLong(name, value);
        commonEditor.apply();
        return value;
    }

    private CommonPrefs() {
    }
}
