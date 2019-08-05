package com.manning.apisecurityinaction.controller;

import java.time.temporal.ChronoUnit;

import com.manning.apisecurityinaction.token.TokenStore;
import org.json.JSONObject;
import spark.*;

import static java.time.Instant.now;

public class TokenController {

    private final TokenStore tokenStore;

    public TokenController(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public JSONObject login(Request request, Response response) {
        String subject = request.attribute("subject");
        var expiry = now().plus(10, ChronoUnit.MINUTES);

        var token = new TokenStore.Token(expiry, subject);
        var tokenId = tokenStore.create(request, token);

        response.status(201);
        return new JSONObject()
                .put("token", tokenId);
    }

    public void validateToken(Request request, Response response) {
        var tokenId = request.headers("X-CSRF-Token");
        if (tokenId == null) return;

        tokenStore.read(request, tokenId).ifPresent(token -> {
            if (now().isBefore(token.expiry)) {
                request.attribute("subject", token.username);
                token.attributes.forEach(request::attribute);
            }
        });
    }

    public JSONObject logout(Request request, Response response) {
        var tokenId = request.headers("X-CSRF-Token");
        if (tokenId == null)
            throw new IllegalArgumentException("missing token header");

        tokenStore.revoke(request, tokenId);

        response.status(200);
        return new JSONObject();
    }
}
