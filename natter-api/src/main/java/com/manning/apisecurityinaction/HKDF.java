package com.manning.apisecurityinaction;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.checkIndex;

public class HKDF {
    public static Key expand(Key masterKey, String context,
                             int outputKeySize, String algorithm)
            throws GeneralSecurityException {
        checkIndex(outputKeySize, 255*32);

        var hmac = Mac.getInstance("HmacSHA256");
        hmac.init(masterKey);

        var output = new byte[outputKeySize];
        var block = new byte[0];
        for (int i = 0; i < outputKeySize; i += 32) {
            hmac.update(block);
            hmac.update(context.getBytes(UTF_8));
            hmac.update((byte) ((i / 32) + 1));
            block = hmac.doFinal();
            System.arraycopy(block, 0, output, i,
                    Math.min(outputKeySize - i, 32));
        }

        return new SecretKeySpec(output, algorithm);
    }
}
