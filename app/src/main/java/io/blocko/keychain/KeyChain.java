package io.blocko.keychain;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v7.app.AppCompatActivity;

import java.io.IOException;
import java.security.KeyStore;
import java.security.ProviderException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import io.blocko.bitcoinj.crypto.DeterministicKey;
import io.blocko.bitcoinj.crypto.HDKeyDerivation;
import io.blocko.bitcoinj.params.MainNetParams;

/**
 * Created by shepelt on 2016. 9. 21..
 */

public class KeyChain {
    private final AppCompatActivity activity;
    private final String keyID;
    private FingerprintManagerCompat fm;
    private Locale locale;

    public KeyChain(AppCompatActivity activity, String keyID) {
        this.keyID = keyID;
        this.activity = activity;
        this.fm = FingerprintManagerCompat.from(activity.getApplicationContext());

        KeyChain.packageName = this.activity.getApplicationContext().getPackageName();
        KeyChain.mDisableBackup = false;
    }

    public boolean isFingerprintAvailable() {
        return fm.isHardwareDetected()
                && fm.hasEnrolledFingerprints();
    }


    public static String packageName;
    public static boolean mDisableBackup;

    public void generateSeed() throws IOException {
        KeyStore mKeyStore = null;
        try {
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);
        } catch (Exception e) {
            throw new IOException("Failed to load keystore", e);
        }

        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
            keyGen.init(new KeyGenParameterSpec.Builder(keyID, KeyProperties.PURPOSE_SIGN).setUserAuthenticationRequired(true).build());
            keyGen.generateKey();
        } catch (Exception e) {
            throw new IOException("Failed to create key", e);
        }
    }

    public void removeSeed() throws IOException {
        try {
            KeyStore mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);
            mKeyStore.deleteEntry(keyID);
        } catch (Exception e) {
            throw new IOException("Failed to remove key", e);
        }
    }

    private Mac initCrypto() throws IOException {
        try {
            KeyStore mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);

            SecretKey key = (SecretKey) mKeyStore.getKey(keyID, null);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac;
        } catch (ProviderException e) {
            if (e.getCause().getMessage().equals("Key user not authenticated")) {
                throw new IOException("Unahutorized to access keystore", e.getCause());
            } else {
                throw new IOException("Failed to access keystore", e.getCause());
            }
        } catch (Exception e) {
            throw new IOException("Failed to access keystore", e.getCause());
        }
    }

    private byte[] fetchSeed(Mac mac) throws IOException {
        try {
            byte[] hmacData = mac.doFinal(keyID.getBytes("UTF-8"));
            return hmacData;
        } catch (ProviderException e) {
            if (e.getCause().getMessage().equals("Key user not authenticated")) {
                throw new IOException("Unahutorized to access keystore", e.getCause());
            } else {
                throw new IOException("Failed to access keystore", e.getCause());
            }
        } catch (Exception e) {
            throw new IOException("Failed to access keystore", e.getCause());
        }
    }

    private static String derivePrivateKey(byte[] seed) {
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(seed);
        String wifKey = master.getPrivateKeyEncoded(MainNetParams.get()).toString();
        return wifKey;
    }

    public boolean isHardwareDetected() {
        return fm.isHardwareDetected();
    }

    public boolean hasEnrolledFingerprints() {
        return fm.hasEnrolledFingerprints();
    }

    public void setLocale(Locale locale) {
        this.locale = locale;
    }

    public void startScan(final Callback callback) throws IOException {
        final Mac mac = this.initCrypto();
        FingerprintAuthenticationDialogFragment mFragment = new FingerprintAuthenticationDialogFragment();
        mFragment.setLocale(this.locale);
        mFragment.setCallback(new FingerprintAuthenticationDialogFragment.Callback() {
            @Override
            public void onSuccess() {
                try {
                    callback.onSuccess(derivePrivateKey(fetchSeed(mac)));
                } catch (IOException e) {
                    callback.onError(-1);
                }
            }

            @Override
            public void onError(int errCode) {
                callback.onError(errCode);
            }

            @Override
            public void onCancel() {
                callback.onCancel();
            }
        });
        mFragment.setCryptoObject(new FingerprintManagerCompat.CryptoObject(mac));
        mFragment.show(this.activity.getSupportFragmentManager(), "FpAuthDialog");
    }

    public static class Locale {
        public String titleText = "";
        public String cancelText = "";
        public String descText = "";
        public String hintText = "";
        public String notRecognizedText = "";
        public String successText = "";
    }

    public interface Callback {
        void onSuccess(String privateKey);
        void onError(int errCode);
        void onCancel();
    }
}
