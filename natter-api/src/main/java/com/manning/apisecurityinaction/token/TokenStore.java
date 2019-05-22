package com.manning.apisecurityinaction.token;

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
    }

}
