package com.manning.apisecurityinaction.token;

import org.json.*;
import spark.Request;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.time.Instant;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.crypto.Cipher.*;

public class JsonTokenStore implements TokenStore {

    private final Key encryptionKey;

    public JsonTokenStore(Key encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    @Override
    public String create(Request request, Token token) {
        var json = new JSONObject();
        json.put("sub", token.username);
        json.put("exp", token.expiry.getEpochSecond());
        json.put("attrs", token.attributes);

        var jsonBytes = json.toString().getBytes(UTF_8);
        var nonceAndCiphertext = encrypt(encryptionKey, jsonBytes);
        var encoder = Base64.getUrlEncoder().withoutPadding();

        return encoder.encodeToString(nonceAndCiphertext[0]) + '.' +
                encoder.encodeToString(nonceAndCiphertext[1]);
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var index = tokenId.indexOf('.');
            if (index == -1) {
                return Optional.empty();
            }
            var nonce = Base64.getUrlDecoder().decode(
                    tokenId.substring(0, index));
            var decoded = Base64.getUrlDecoder().decode(
                    tokenId.substring(index + 1));
            var decrypted = decrypt(encryptionKey, nonce, decoded);
            var json = new JSONObject(new String(decrypted, UTF_8));
            var expiry = Instant.ofEpochSecond(json.getInt("exp"));
            var username = json.getString("sub");
            var attrs = json.getJSONObject("attrs");

            var token = new Token(expiry, username);
            for (var key : attrs.keySet()) {
                token.attributes.put(key, attrs.getString(key));
            }

            return Optional.of(token);
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    static byte[][] encrypt(Key key, byte[] message) {
        try {
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            var nonce = new byte[cipher.getBlockSize()];
            new SecureRandom().nextBytes(nonce);
            cipher.init(ENCRYPT_MODE, key, new IvParameterSpec(nonce));
            var encrypted = cipher.doFinal(message);
            return new byte[][]{nonce, encrypted};
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] decrypt(Key key, byte[] nonce, byte[] ciphertext) {
        try {
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(DECRYPT_MODE, key, new IvParameterSpec(nonce));
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
