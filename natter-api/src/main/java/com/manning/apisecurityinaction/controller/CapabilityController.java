package com.manning.apisecurityinaction.controller;

import java.net.*;
import java.time.Instant;
import java.util.Objects;

import com.manning.apisecurityinaction.token.SecureTokenStore;
import com.manning.apisecurityinaction.token.TokenStore.Token;
import spark.*;

public class CapabilityController {

    private final SecureTokenStore tokenStore;

    public CapabilityController(SecureTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public URI createUri(Request request, String path, String perms) {
        var token = new Token(Instant.MAX, null);
        token.attributes.put("path", path);
        token.attributes.put("perms", perms);

        var tokenId = tokenStore.create(request, token);

        var base = URI.create(request.url());
        try {
            return new URI(base.getScheme(), tokenId, base.getHost(),
                    base.getPort(), path, null, null);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public void lookupPermissions(Request request, Response response) {
        var authHeader = request.headers("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer "))
            return;
        var tokenId = authHeader.substring(7).trim();

        tokenStore.read(request, tokenId).ifPresent(token -> {
            var tokenPath = token.attributes.get("path");
            if (Objects.equals(tokenPath, request.pathInfo())) {
                request.attribute("perms",
                        token.attributes.get("perms"));
            }
        });
    }
}
