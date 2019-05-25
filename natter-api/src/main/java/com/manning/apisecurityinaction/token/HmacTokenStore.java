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
        var parts = tokenId.split("\\.");
        if (parts.length != 3) return Optional.empty();

        var header = parts[0];
        var payload = parts[1];
        var tag = parts[2];

        var decoder = Base64.getUrlDecoder();
        var provided = decoder.decode(tag);
        var computed = hmac(header + '.' + payload);

        if (!MessageDigest.isEqual(provided, computed)) {
            return Optional.empty();
        }

        var jwtHeader = new JSONObject(
                new String(decoder.decode(header), UTF_8));
        if (!"JWT".equals(jwtHeader.getString("typ"))) {
            return Optional.empty();
        }
        if (!jwsAlgorithm(macKey).equals(jwtHeader.getString("alg"))) {
            return Optional.empty();
        }

        return delegate.read(request, payload);
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
