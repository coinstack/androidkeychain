package io.blocko.keychain;

import android.Manifest;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v4.app.FragmentManager;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

import java.io.IOException;

import javax.crypto.Mac;


public class MainActivity extends AppCompatActivity {
    private static final int FINGERPRINT_PERMISSION_REQUEST_CODE = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        final KeyChain keychain = new KeyChain(this, "TESTKEY");


        final Button button = (Button) findViewById(R.id.button);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                System.out.println("button 1");
                try {
                    keychain.generateSeed();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        });
        final Button button2 = (Button) findViewById(R.id.button2);


        button2.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                System.out.println("button 2");
                if (isFingerprintPermissionGranted()) {
                    if (keychain.isHardwareDetected()) {
                        System.out.println("has fingerprint sensor");
                    } else {
                        System.out.println("has no fingerprint sensor");
                    }
                    if (keychain.hasEnrolledFingerprints()) {
                        System.out.println("has fingerprint enrolled");
                    } else {
                        System.out.println("has no fingerprint enrolled");
                    }


                    if (keychain.isFingerprintAvailable()) {
                        // do fingerprint auth
                        try {

                            KeyChain.Locale locale = new KeyChain.Locale();
                            locale.descText = "설명";
                            locale.cancelText = "취소";
                            locale.titleText = "타이틀";
                            locale.hintText = "지문";
                            locale.successText = "인식성공";
                            locale.notRecognizedText = "인식실패";
                            keychain.setLocale(locale);

                            keychain.startScan(new KeyChain.Callback() {
                                @Override
                                public void onSuccess(String privateKey) {
                                    System.out.println(privateKey);
                                }

                                @Override
                                public void onError(int errCode) {
                                    System.out.println(errCode);
                                    System.out.println("scan failed");
                                }

                                @Override
                                public void onCancel() {
                                    System.out.println("cancelled");
                                }
                            });
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }


                } else {
                    System.out.println("no fingerprint permission");
                    requestPermission();
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
}
