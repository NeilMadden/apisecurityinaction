package com.manning.apisecurityinaction;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.checkIndex;

public class HKDF {
    public static Key extract(byte[] salt, byte[] inputKeyMaterial)
            throws GeneralSecurityException {
        var hmac = Mac.getInstance("HmacSHA256");
        if (salt == null) {
            salt = new byte[hmac.getMacLength()];
        }
        hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return new SecretKeySpec(hmac.doFinal(inputKeyMaterial),
                "HmacSHA256");
    }

    public static Key expand(Key masterKey, String context,
                             int outputKeySize, String algorithm)
            throws GeneralSecurityException {
        return expand(masterKey, context.getBytes(UTF_8),
                outputKeySize, algorithm);
    }

    public static Key expand(Key masterKey, byte[] context,
                             int outputKeySize, String algorithm)
            throws GeneralSecurityException {

        checkIndex(outputKeySize, 255*32);

        var hmac = Mac.getInstance("HmacSHA256");
        hmac.init(masterKey);

        var output = new byte[outputKeySize];
        var block = new byte[0];
        for (int i = 0; i < outputKeySize; i += 32) {
            hmac.update(block);
            hmac.update(context);
            hmac.update((byte) ((i / 32) + 1));
            block = hmac.doFinal();
            System.arraycopy(block, 0, output, i,
                    Math.min(outputKeySize - i, 32));
        }

        return new SecretKeySpec(output, algorithm);
    }
}
