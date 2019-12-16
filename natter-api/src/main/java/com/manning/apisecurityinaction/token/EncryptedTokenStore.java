package com.manning.apisecurityinaction.token;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Optional;

import spark.Request;

import static javax.crypto.Cipher.*;

public class EncryptedTokenStore implements SecureTokenStore {

    private final TokenStore delegate;
    private final Key encryptionKey;

    public EncryptedTokenStore(TokenStore delegate, Key encryptionKey) {
        this.delegate = delegate;
        this.encryptionKey = encryptionKey;
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = delegate.create(request, token);

        var nonceAndCiphertext = encrypt(encryptionKey,
                Base64url.decode(tokenId));

        return Base64url.encode(nonceAndCiphertext[0]) + '.'
                + Base64url.encode(nonceAndCiphertext[1]);
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var index = tokenId.indexOf('.');
        if (index == -1) { return Optional.empty(); }

        var nonce = Base64url.decode(tokenId.substring(0, index));
        var encrypted = Base64url.decode(tokenId.substring(index + 1));
        var decrypted = decrypt(encryptionKey, nonce, encrypted);

        return delegate.read(request, Base64url.encode(decrypted));
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var index = tokenId.indexOf('.');
        if (index == -1) { return; }

        var nonce = Base64url.decode(tokenId.substring(0, index));
        var encrypted = Base64url.decode(tokenId.substring(index + 1));
        var decrypted = decrypt(encryptionKey, nonce, encrypted);

        delegate.revoke(request, Base64url.encode(decrypted));
    }

    static byte[][] encrypt(Key key, byte[] message) {
        try {
            var cipher = Cipher.getInstance("ChaCha20-Poly1305");
            var nonce = new byte[12];
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
            var cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(DECRYPT_MODE, key, new IvParameterSpec(nonce));
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
