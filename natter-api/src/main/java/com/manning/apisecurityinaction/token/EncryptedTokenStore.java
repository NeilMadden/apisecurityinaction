package com.manning.apisecurityinaction.token;

import spark.Request;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.*;

import static javax.crypto.Cipher.*;

public class EncryptedTokenStore implements TokenStore {

    private final TokenStore delegate;
    private final Key encryptionKey;

    private final Base64.Encoder encoder;
    private final Base64.Decoder decoder;

    public EncryptedTokenStore(TokenStore delegate, Key encryptionKey) {
        this.delegate = delegate;
        this.encryptionKey = encryptionKey;
        this.encoder = Base64.getUrlEncoder().withoutPadding();
        this.decoder = Base64.getUrlDecoder();
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = delegate.create(request, token);

        var nonceAndCiphertext = encrypt(encryptionKey,
                decoder.decode(tokenId));

        return encoder.encodeToString(nonceAndCiphertext[0]) + '.'
                + encoder.encodeToString(nonceAndCiphertext[1]);
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var index = tokenId.indexOf('.');
        if (index == -1) { return Optional.empty(); }

        var nonce = decoder.decode(tokenId.substring(0, index));
        var encrypted = decoder.decode(tokenId.substring(index + 1));
        var decrypted = decrypt(encryptionKey, nonce, encrypted);

        return delegate.read(request, encoder.encodeToString(decrypted));
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var index = tokenId.indexOf('.');
        if (index == -1) { return; }

        var nonce = decoder.decode(tokenId.substring(0, index));
        var encrypted = decoder.decode(tokenId.substring(index + 1));
        var decrypted = decrypt(encryptionKey, nonce, encrypted);

        delegate.revoke(request, encoder.encodeToString(decrypted));
    }

    static byte[][] encrypt(Key key, byte[] message) {
        try {
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            var nonce = new byte[16];
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
