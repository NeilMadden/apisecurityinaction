package com.manning.apisecurityinaction.token;

import javax.crypto.Mac;
import java.security.*;
import java.util.Optional;

import spark.Request;

import static java.nio.charset.StandardCharsets.UTF_8;

public class HmacTokenStore implements SecureTokenStore {

    private final TokenStore delegate;
    private final Key macKey;

    private HmacTokenStore(TokenStore delegate, Key macKey) {
        this.delegate = delegate;
        this.macKey = macKey;
    }
    public static SecureTokenStore wrap(ConfidentialTokenStore store,
                                        Key macKey) {
        return new HmacTokenStore(store, macKey);
    }
    public static AuthenticatedTokenStore wrap(TokenStore store,
                                          Key macKey) {
        return new HmacTokenStore(store, macKey);
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = delegate.create(request, token);
        var tag = hmac(tokenId);

        return tokenId + '.' + Base64url.encode(tag);
    }

    private byte[] hmac(String tokenId) {
        try {
            var mac = Mac.getInstance(macKey.getAlgorithm());
            mac.init(macKey);
            return mac.doFinal(tokenId.getBytes(UTF_8));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var index = tokenId.lastIndexOf('.');
        if (index == -1) return Optional.empty();

        var realTokenId = tokenId.substring(0, index);
        var tag = tokenId.substring(index + 1);

        var provided = Base64url.decode(tag);
        var computed = hmac(realTokenId);

        if (!MessageDigest.isEqual(provided, computed)) {
            return Optional.empty();
        }

        return delegate.read(request, realTokenId);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var index = tokenId.lastIndexOf('.');
        if (index == -1) return;
        var realTokenId = tokenId.substring(0, index);

        var provided = Base64url.decode(tokenId.substring(index + 1));
        var computed = hmac(realTokenId);

        if (!MessageDigest.isEqual(provided, computed)) {
            return;
        }

        delegate.revoke(request, realTokenId);
    }
}
