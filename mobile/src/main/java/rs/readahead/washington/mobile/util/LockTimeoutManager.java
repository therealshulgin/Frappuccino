package rs.readahead.washington.mobile.util;


import rs.readahead.washington.mobile.data.sharedpref.Preferences;


public class LockTimeoutManager {
    public static long IMMEDIATE_SHUTDOWN = 0L;
    public static long ONE_MINUTES_SHUTDOWN = 60000L;

    public long getLockTimeout() {
        return Preferences.getLockTimeout();
    }
}
