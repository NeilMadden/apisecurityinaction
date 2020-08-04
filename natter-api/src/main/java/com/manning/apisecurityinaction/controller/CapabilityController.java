package com.manning.apisecurityinaction.controller;

import com.manning.apisecurityinaction.token.SecureTokenStore;
import com.manning.apisecurityinaction.token.TokenStore.Token;
import org.json.JSONObject;
import spark.*;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

import static java.time.Instant.now;

public class CapabilityController {

    private final SecureTokenStore tokenStore;

    public CapabilityController(SecureTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public URI createUri(Request request, String path, String perms,
                         Duration expiryDuration) {
        var subject = (String) request.attribute("subject");
        var token = new Token(now().plus(expiryDuration), subject);
        token.attributes.put("path", path);
        token.attributes.put("perms", perms);

        var tokenId = tokenStore.create(request, token);

        var uri = URI.create(request.uri());
        return uri.resolve(path + "?access_token=" + tokenId);
    }

    public void lookupPermissions(Request request, Response response) {
        var tokenId = request.queryParams("access_token");
        if (tokenId == null) { return; }

        tokenStore.read(request, tokenId).ifPresent(token -> {
            if (!Objects.equals(token.username, request.attribute("subject"))) {
                return;
            }

            var tokenPath = token.attributes.get("path");
            if (Objects.equals(tokenPath, request.pathInfo())) {
                request.attribute("perms",
                        token.attributes.get("perms"));
            }
        });
    }

    public JSONObject share(Request request, Response response) {
        var json = new JSONObject(request.body());

        var capUri = URI.create(json.getString("uri"));
        var path = capUri.getPath();
        var query = capUri.getQuery();
        var tokenId = query.substring(query.indexOf('=') + 1);

        var token = tokenStore.read(request, tokenId).orElseThrow();
        if (!Objects.equals(token.attributes.get("path"), path)) {
            throw new IllegalArgumentException("incorrect path");
        }

        var tokenPerms = token.attributes.get("perms");
        var perms = json.optString("perms", tokenPerms);
        if (!tokenPerms.contains(perms)) {
            Spark.halt(403);
        }

        var user = json.getString("user");
        var newToken = new Token(token.expiry, user);
        newToken.attributes.put("path", path);
        newToken.attributes.put("perms", perms);

        var newTokenId = tokenStore.create(request, newToken);
        var uri = URI.create(request.uri());
        var newCapUri = uri.resolve(path + "?access_token=" + newTokenId);
        return new JSONObject()
                .put("uri", newCapUri);
    }
}
