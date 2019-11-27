package com.manning.apisecurityinaction.controller;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;

import com.manning.apisecurityinaction.token.SecureTokenStore;
import com.manning.apisecurityinaction.token.TokenStore.Token;
import spark.*;

import static java.time.temporal.ChronoUnit.DAYS;

public class CapabilityController {
    private static final Instant NON_EXPIRING =
            Instant.EPOCH.plus(10000 * 365, DAYS);

    private final SecureTokenStore tokenStore;

    public CapabilityController(SecureTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public URI createUri(Request request, String path, String perms) {
        var token = new Token(NON_EXPIRING, null);
        token.attributes.put("path", path);
        token.attributes.put("perms", perms);

        var tokenId = tokenStore.create(request, token);

        var base = URI.create(request.url());
        return base.resolve(path + "?access_token=" + tokenId);
    }

    public void lookupPermissions(Request request, Response response) {
        var tokenId = request.queryParams("access_token");
        if (tokenId == null) return;

        tokenStore.read(request, tokenId).ifPresent(token -> {
            var tokenPath = token.attributes.get("path");
            if (Objects.equals(tokenPath, request.pathInfo())) {
                request.attribute("perms",
                        token.attributes.get("perms"));
            }
        });
    }
}
