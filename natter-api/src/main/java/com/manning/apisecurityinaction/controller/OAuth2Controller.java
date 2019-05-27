package com.manning.apisecurityinaction.controller;

import com.manning.apisecurityinaction.oauth2.*;
import com.manning.apisecurityinaction.token.*;
import org.json.JSONObject;
import spark.*;

import java.time.*;
import java.util.*;

public class OAuth2Controller {

    private final SecureTokenStore accessTokenStore;
    private final Map<String, GrantType> grantTypes;

    private final Duration validityDuration;

    public OAuth2Controller(SecureTokenStore accessTokenStore,
                            Map<String, GrantType> grantTypes) {
        this.accessTokenStore = accessTokenStore;
        this.grantTypes = grantTypes;

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

        var access = grantType.validate(request, scope);
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
}
