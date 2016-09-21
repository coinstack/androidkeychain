package io.blocko.keychain;

/**
 * Created by shepelt on 2016. 9. 21..
 */

public class KeyChain {

    public static String packageName;
    public static int mMaxAttempts;
    public static boolean mDisableBackup;

    public static void onCancelled() {
        System.out.println("cancelled");
    }

    public static void onError(String s) {
        System.out.println("error : " + s);
    }

    public static void onAuthenticated(boolean b) {
        System.out.println("authenticated");
    }
}
