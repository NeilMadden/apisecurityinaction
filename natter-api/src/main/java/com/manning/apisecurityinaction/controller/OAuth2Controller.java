package com.manning.apisecurityinaction.controller;

import com.manning.apisecurityinaction.oauth2.*;
import com.manning.apisecurityinaction.token.*;
import org.json.JSONObject;
import spark.*;

import java.time.*;
import java.util.*;

import static spark.Spark.halt;

public class OAuth2Controller {

    private final SecureTokenStore accessTokenStore;
    private final Map<String, GrantType> grantTypes;
    private final Map<String, Client> clients;

    private final Duration validityDuration;

    public OAuth2Controller(SecureTokenStore accessTokenStore,
                            Map<String, GrantType> grantTypes,
                            Map<String, Client> clients) {
        this.accessTokenStore = accessTokenStore;
        this.grantTypes = grantTypes;
        this.clients = clients;

        this.validityDuration = Duration.ofMinutes(10);
    }

    public JSONObject issueTokens(Request request, Response response) {

        var grantType = grantTypes.get(request.queryParams("grant_type"));
        if (grantType == null) {
            response.status(400);
            return new JSONObject()
                    .put("error", "unsupported_grant_type");
        }

        var scope = Set.of(
                request.queryParamOrDefault("scope", "").split(" "));

        for (var s : scope) {
            if (!s.matches("^[\\x21\\x23-\\x5B\\x5D-\\x7E]*$")) {
                response.status(400);
                return new JSONObject()
                        .put("error", "invalid_scope")
                        .put("error_description",
                                "illegal character in scope");
            }
        }

        var client = clients.get(request.queryParams("client_id"));
        if (client != null) {
            if (!client.allowedScope.containsAll(scope)) {
                response.status(403);
                return new JSONObject()
                        .put("error", "access_denied");
            }
        }

        var access = grantType.validate(request, client, scope);
        if (!access.granted) {
            response.status(400);
            return new JSONObject()
                    .put("error", "invalid_scope");
        }

        var expiry = Instant.now().plus(validityDuration);
        var accessToken = new TokenStore.Token(expiry, access.resourceOwner);
        accessToken.attributes.put("scope", String.join(" ", access.scope));

        var tokenId = accessTokenStore.create(request, accessToken);

        return new JSONObject()
                .put("access_token", tokenId)
                .put("token_type", "Bearer")
                .put("expires_in", validityDuration.toSeconds())
                .put("scope", accessToken.attributes.get("scope"));
    }

    public Filter requireScope(String method, String scope) {
        return (request, response) -> {
            if (!request.requestMethod().equals(method)) {
                return;
            }

            var requestScope = request.<String>attribute("scope");
            if (requestScope != null) {
                var scopeSet = Set.of(requestScope.split(" "));
                if (!scopeSet.contains(scope)) {
                    response.header("WWW-Authenticate",
                            "Bearer error=\"insufficient_scope\"," +
                                    "scope=\"" + scope + "\"");
                    halt(401);
                }
            }
        };
    }
}
