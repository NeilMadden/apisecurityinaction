package com.manning.apisecurityinaction;

import com.upokecenter.cbor.CBORObject;
import org.cryptomator.siv.SivMode;

import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class AesSivExample {
    public static void main(String... args) throws Exception {
        var psk = PskServer.loadPsk("changeit".toCharArray());
        var macKey = new SecretKeySpec(Arrays.copyOfRange(psk, 0, 16),
                "AES");
        var encKey = new SecretKeySpec(Arrays.copyOfRange(psk, 16, 32),
                "AES");

        var randomIv = new byte[16];
        new SecureRandom().nextBytes(randomIv);
        var header = "Test header".getBytes();
        var body = CBORObject.NewMap()
                .Add("sensor", "F5671434")
                .Add("reading", 1234).EncodeToBytes();

        var siv = new SivMode();
        var ciphertext = siv.encrypt(encKey, macKey, body,
                header, randomIv);
        var plaintext = siv.decrypt(encKey, macKey, ciphertext,
                header, randomIv);
        assert Arrays.equals(plaintext, body);
    }
}
