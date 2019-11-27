package com.manning.apisecurityinaction.token;

import org.json.JSONObject;
import spark.Request;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public interface TokenStore {

    String create(Request request, Token token);
    Optional<Token> read(Request request, String tokenId);
    void revoke(Request request, String tokenId);

    class Token {
        public final Instant expiry;
        public final String username;
        public final Map<String, String> attributes;

        public Token(Instant expiry, String username) {
            this.expiry = expiry;
            this.username = username;
            this.attributes = new ConcurrentHashMap<>();
        }

        public JSONObject toJson() {
            return new JSONObject()
                    .put("exp", expiry.getEpochSecond())
                    .put("sub", username)
                    .put("attrs", attributes);
        }

        public static Token fromJson(JSONObject json) {
            var expiry = Instant.ofEpochSecond(json.getLong("exp"));
            var user = json.optString("sub");
            var attrs = new LinkedHashMap<String, String>();
            json.getJSONObject("attrs").toMap()
                    .forEach((key, value) -> attrs.put(key, value.toString()));

            var token = new Token(expiry, user);
            token.attributes.putAll(attrs);
            return token;
        }
    }

}
