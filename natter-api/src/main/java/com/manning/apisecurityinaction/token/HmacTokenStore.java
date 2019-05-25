package com.manning.apisecurityinaction.token;

import spark.Request;

import javax.crypto.Mac;
import java.security.*;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class HmacTokenStore implements TokenStore {

    private final TokenStore delegate;
    private final Key macKey;

    public HmacTokenStore(TokenStore delegate, Key macKey) {
        this.delegate = delegate;
        this.macKey = macKey;
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = delegate.create(request, token);
        var tag = hmac(tokenId);

        return tokenId + '.' +
                Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(tag);
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

        var decoder = Base64.getUrlDecoder();
        var provided = decoder.decode(tag);
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

        var provided = Base64.getUrlDecoder()
                .decode(tokenId.substring(index + 1));
        var computed = hmac(realTokenId);

        if (!MessageDigest.isEqual(provided, computed)) {
            return;
        }

        delegate.revoke(request, realTokenId);
    }
}
