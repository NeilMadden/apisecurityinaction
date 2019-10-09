package com.manning.apisecurityinaction.controller;

import java.net.URI;
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

        var uri = URI.create(request.url());
        return uri.resolve(path + "?access_token=" + tokenId);
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
