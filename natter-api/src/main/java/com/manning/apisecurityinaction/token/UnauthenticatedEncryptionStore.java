package com.manning.apisecurityinaction.token;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Optional;

import spark.Request;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * This token store encrypts the contents of the token using AES in
 * unauthenticated counter mode. This is provided purely as an example
 * of using types to enforce security properties. You should use the
 * {@link EncryptedTokenStore} or {@link EncryptedJwtTokenStore}
 * instead of this store.
 */
public class UnauthenticatedEncryptionStore implements ConfidentialTokenStore {

    private final Key encKey;
    private final TokenStore delegate;

    public UnauthenticatedEncryptionStore(Key encKey, TokenStore delegate) {
        this.encKey = encKey;
        this.delegate = delegate;
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = delegate.create(request, token);
        return encrypt(tokenId.getBytes(UTF_8));
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        return decrypt(tokenId).flatMap(tok -> delegate.read(request, tok));
    }

    @Override
    public void revoke(Request request, String tokenId) {
        decrypt(tokenId).ifPresent(tok -> delegate.revoke(request, tok));
    }

    private String encrypt(byte[] data) {
        try {
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, encKey);
            var ciphertext = cipher.doFinal(data);
            var iv = cipher.getIV();
            return Base64url.encode(iv) + '.' + Base64url.encode(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private Optional<String> decrypt(String encrypted) {
        var index = encrypted.indexOf('.');
        if (index == -1) return Optional.empty();
        var iv = Base64url.decode(encrypted.substring(0, index));
        var ciphertext = Base64url.decode(encrypted.substring(index + 1));
        try {
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, encKey,
                    new IvParameterSpec(iv));
            var plaintext = cipher.doFinal(ciphertext);
            return Optional.of(new String(plaintext, UTF_8));
        } catch (GeneralSecurityException e) {
            return Optional.empty();
        }
    }
}
