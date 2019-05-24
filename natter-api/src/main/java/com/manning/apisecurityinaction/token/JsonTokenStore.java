package com.manning.apisecurityinaction.token;

import org.json.*;
import spark.Request;

import java.time.Instant;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JsonTokenStore implements TokenStore {

    @Override
    public String create(Request request, Token token) {
        var json = new JSONObject();
        json.put("sub", token.username);
        json.put("exp", token.expiry.getEpochSecond());
        json.put("aud", List.of("https://localhost:4567"));
        json.put("attrs", token.attributes);

        var jsonBytes = json.toString().getBytes(UTF_8);
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(jsonBytes);
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var decoded = Base64.getUrlDecoder().decode(tokenId);
            var json = new JSONObject(new String(decoded, UTF_8));
            var expiry = Instant.ofEpochSecond(json.getInt("exp"));
            var username = json.getString("sub");
            var audience = json.getJSONArray("aud").toList();
            var attrs = json.getJSONObject("attrs");

            if (!audience.contains("https://locahost:4567")) {
                return Optional.empty();
            }

            var token = new Token(expiry, username);
            for (var key : attrs.keySet()) {
                token.attributes.put(key, attrs.getString(key));
            }

            return Optional.of(token);
        } catch (JSONException e) {
            return Optional.empty();
        }
    }
}
