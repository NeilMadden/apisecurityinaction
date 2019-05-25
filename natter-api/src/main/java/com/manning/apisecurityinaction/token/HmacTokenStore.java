package com.manning.apisecurityinaction.token;

import org.json.JSONObject;
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
        var header = new JSONObject()
                .put("alg", jwsAlgorithm(macKey))
                .put("typ", "JWT").toString();
        header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(header.getBytes(UTF_8));
        tokenId = header + '.' + tokenId;
        var tag = hmac(tokenId);

        return tokenId + '.' +
                Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(tag);
    }

    private byte[] hmac(String tokenId) {
        try {
            var mac = Mac.getInstance(macKey.getAlgorithm());
            mac.init(macKey);
            return mac.doFinal(
                    tokenId.getBytes(UTF_8));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var headerIndex = tokenId.indexOf('.');
        var tagIndex = tokenId.lastIndexOf('.');

        var decoder = Base64.getUrlDecoder();
        var decodedHeader = decoder.decode(
                tokenId.substring(0, headerIndex));
        var header = new JSONObject(new String(decodedHeader, UTF_8));

        if (!"JWT".equals(header.getString("typ"))) {
            return Optional.empty();
        }
        if (!jwsAlgorithm(macKey).equals(header.getString("alg"))) {
            return Optional.empty();
        }

        var realTokenId = tokenId.substring(headerIndex + 1, tagIndex);
        var provided = decoder.decode(tokenId.substring(tagIndex + 1));
        var computed = hmac(tokenId.substring(0, tagIndex));

        if (!MessageDigest.isEqual(provided, computed)) {
            return Optional.empty();
        }

        return delegate.read(request, realTokenId);
    }

    private static String jwsAlgorithm(Key key) {
        switch (key.getAlgorithm()) {
            case "HmacSHA256":
            case "1.2.840.113549.2.9":
                return "HS256";
            case "HmacSHA384":
            case "1.2.840.113549.2.10":
                return "HS384";
            case "HmacSHA512":
            case "1.2.840.113549.2.11":
                return "HS512";
            default:
                throw new IllegalStateException(
                        "unknown algorithm: " + key.getAlgorithm());
        }
    }
}
