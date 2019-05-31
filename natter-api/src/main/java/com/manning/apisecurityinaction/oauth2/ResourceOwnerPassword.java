package com.manning.apisecurityinaction.oauth2;

import com.lambdaworks.crypto.SCryptUtil;
import org.dalesbred.Database;
import spark.Request;

import java.util.Set;

public class ResourceOwnerPassword implements GrantType {

    private final Database database;

    public ResourceOwnerPassword(Database database) {
        this.database = database;
    }

    @Override
    public AccessDecision validate(Request request, Client client,
                                   Set<String> scope) {
        if (!"application/x-www-form-urlencoded".equals(
                request.contentType())) {
            throw new IllegalArgumentException(
                    "request must be form-urlencoded");
        }

        var username = request.queryParams("username");
        var password = request.queryParams("password");

        var hash = database.findOptional(String.class,
                "SELECT pw_hash FROM users WHERE user_id = ?",
                username);

        if (hash.isPresent() && SCryptUtil.check(password, hash.get())) {
            return AccessDecision.allowed(username, scope);
        }

        return AccessDecision.denied();
    }
}
