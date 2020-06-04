package com.manning.apisecurityinaction;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.util.Arrays;

public class RatchetExample {

    public static void main(String... args) throws Exception {
        var key = PskServer.loadPsk(args[0].toCharArray());
        System.out.println("Original key: " + Hex.toHexString(key));
        for (int i = 0; i < 10; ++i) {
            var newKey = ratchet(key);
            Arrays.fill(key, (byte) 0);
            key = newKey;
            System.out.println("Next key: " + Hex.toHexString(key));
        }
    }

    private static byte[] ratchet(byte[] oldKey) throws Exception {
        var cipher = Cipher.getInstance("AES/CTR/NoPadding");
        var iv = new byte[16];
        Arrays.fill(iv, (byte) 0xFF);
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(oldKey, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(new byte[32]);
    }
}
