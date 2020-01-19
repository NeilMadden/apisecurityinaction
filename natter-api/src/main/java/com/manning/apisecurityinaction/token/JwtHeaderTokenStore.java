package com.manning.apisecurityinaction.token;

import java.util.*;

import org.json.JSONObject;
import spark.Request;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JwtHeaderTokenStore implements TokenStore {

    private final TokenStore delegate;
    private final JSONObject header;

    public JwtHeaderTokenStore(TokenStore delegate, JSONObject header) {
        this.delegate = delegate;
        this.header = header;
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = delegate.create(request, token);
        var headerBytes = header.toString().getBytes(UTF_8);
        return Base64url.encode(headerBytes) + '.' + tokenId;
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var index = tokenId.indexOf('.');
        if (index == -1) return Optional.empty();

        var encodedHeader = tokenId.substring(0, index);
        var realTokenId = tokenId.substring(index + 1);

        var decodedHeader = Base64url.decode(encodedHeader);
        var suppliedHeader = new JSONObject(
                new String(decodedHeader, UTF_8));

        for (var expected : this.header.keySet()) {
            if (!Objects.equals(this.header.get(expected),
                    suppliedHeader.get(expected))) {
                return Optional.empty();
            }
        }

        return delegate.read(request, realTokenId);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var index = tokenId.indexOf('.');
        if (index == -1) return;

        var realTokenId = tokenId.substring(index + 1);
        delegate.revoke(request, realTokenId);
    }
}
