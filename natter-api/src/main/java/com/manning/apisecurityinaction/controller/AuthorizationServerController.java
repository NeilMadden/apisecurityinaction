package com.manning.apisecurityinaction.controller;

import com.lambdaworks.crypto.SCryptUtil;
import com.manning.apisecurityinaction.token.*;
import org.dalesbred.Database;
import org.json.JSONObject;
import spark.*;

import java.security.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AuthorizationServerController {

    private final SecureTokenStore tokenStore;
    private final Database database;
    private final JSONObject clientConfig;

    public AuthorizationServerController(SecureTokenStore tokenStore,
                                         Database database,
                                         JSONObject clientConfig) {
        this.tokenStore = tokenStore;
        this.database = database;
        this.clientConfig = clientConfig;
    }

    public JSONObject issueAccessToken(Request request, Response response) {

        var grantType = request.queryMap("grant_type").value();
        if (!"password".equals(grantType)) {
            throw new IllegalArgumentException("unsupported_grant_type");
        }

        var client = authenticateClient(request);
        var username = request.queryMap("username").value();
        var password = request.queryMap("password").value();
        var scope = request.queryMap("scope").value();

        if (scope == null || scope.isBlank() ||
                username == null || username.isBlank() ||
                password == null || password.isBlank()) {
            throw new IllegalArgumentException("invalid_request");
        }

        if (!username.matches(UserController.USERNAME_PATTERN)) {
            throw new IllegalArgumentException("invalid_request");
        }
        scope = validateScope(scope, client);

        var hash = database.findOptional(String.class,
                "SELECT pw_hash FROM users WHERE user_id = ?", username);

        if (hash.isPresent() && SCryptUtil.check(password, hash.get())) {
            var expiry = Instant.now().plus(1, ChronoUnit.HOURS);
            var token = new TokenStore.Token(expiry, username);
            token.attributes.put("scope", scope);

            var tokenId = tokenStore.create(request, token);
            return new JSONObject()
                    .put("access_token", tokenId)
                    .put("token_type", "Bearer")
                    .put("expires_in", 3600)
                    .put("scope", scope);
        } else {
            throw new IllegalArgumentException("invalid_grant");
        }
    }

    private String validateScope(String scope, JSONObject client) {
        var allowedScope = client.getJSONArray("allowed_scope").toList();
        var requestScope = scope.split(" ");

        var resultScope = new TreeSet<String>();
        for (var requested : requestScope) {
            if (allowedScope.contains(requested)) {
                resultScope.add(requested);
            }
        }

        return String.join(" ", resultScope);
    }

    private JSONObject authenticateClient(Request request) {
        var clientId = request.queryMap("client_id").value();
        var secret = request.queryMap("client_secret").value();

        if (clientId == null || clientId.isBlank() ||
                secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("invalid_client");
        }

        var client = clientConfig.optJSONObject(clientId);
        if (client == null) {
            throw new IllegalArgumentException("invalid_client");
        }

        var expected = Base64.getDecoder().decode(
                client.getString("secret_hash"));
        var provided = hash(secret);

        if (!MessageDigest.isEqual(expected, provided)) {
            throw new IllegalArgumentException("invalid_client");
        }

        return client;
    }

    public static byte[] hash(String clientSecret) {
        try {
            var sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(clientSecret.getBytes(UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
