package io.blocko.keychain;

import android.Manifest;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import io.blocko.bitcoinj.crypto.DeterministicKey;
import io.blocko.bitcoinj.crypto.HDKeyDerivation;
import io.blocko.bitcoinj.params.MainNetParams;


public class MainActivity extends AppCompatActivity {
    private static final int FINGERPRINT_PERMISSION_REQUEST_CODE = 0;
    private FingerprintManagerCompat fm;

    public static String byteArrayToHex(byte[] ba) {
        if (ba == null || ba.length == 0) {
            return null;
        }

        StringBuffer sb = new StringBuffer(ba.length * 2);
        String hexNumber;
        for (int x = 0; x < ba.length; x++) {
            hexNumber = "0" + Integer.toHexString(0xff & ba[x]);

            sb.append(hexNumber.substring(hexNumber.length() - 2));
        }
        return sb.toString();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final Button button = (Button) findViewById(R.id.button);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                System.out.println("button 1");
                try {
                    generateSeed("TESTKEY");
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        });
        final Button button2 = (Button) findViewById(R.id.button2);
        this.fm = FingerprintManagerCompat.from(this.getApplicationContext());
        button2.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                System.out.println("button 2");
                // TODO: auth
                if (isFingerprintPermissionGranted()) {
                    if (fm.isHardwareDetected()) {
                        System.out.println("has fingerprint sensor");
                    } else {
                        System.out.println("has no fingerprint sensor");
                    }
                    if (fm.hasEnrolledFingerprints()) {
                        System.out.println("has fingerprint enrolled");
                    } else {
                        System.out.println("has no fingerprint enrolled");
                    }
                } else {
                    System.out.println("no fingerprint permission");
                    requestPermission();
                }

            }
        });

        final Button button3 = (Button) findViewById(R.id.button3);
        button3.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                System.out.println("button 3");
                try {
                    System.out.println(derivePrivateKey(fetchSeed("TESTKEY")));
                    removeSeed("TESTKEY");
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    public void requestPermission() {
        ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.USE_FINGERPRINT},
                FINGERPRINT_PERMISSION_REQUEST_CODE);
    }

    public boolean isFingerprintPermissionGranted() {
        return ActivityCompat.checkSelfPermission(
                MainActivity.this, Manifest.permission.USE_FINGERPRINT)
                == PackageManager.PERMISSION_GRANTED;
    }

    public boolean isFingerprintAvailable() {
        return fm.isHardwareDetected()
                && fm.hasEnrolledFingerprints();
    }

    public static void generateSeed(String keyID) throws IOException {
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

    public static void removeSeed(String keyID) throws IOException {
        try {
            KeyStore mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);
            mKeyStore.deleteEntry(keyID);
        } catch (Exception e) {
            throw new IOException("Failed to remove key", e);
        }
    }

    public static byte[] fetchSeed(String keyID) throws IOException {
        try {
            KeyStore mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);

            SecretKey key = (SecretKey) mKeyStore.getKey(keyID, null);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
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

    public static String derivePrivateKey(byte[] seed) {
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(seed);
        String wifKey = master.getPrivateKeyEncoded(MainNetParams.get()).toString();
        return wifKey;
    }
}
