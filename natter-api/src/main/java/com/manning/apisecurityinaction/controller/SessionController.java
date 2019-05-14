package com.manning.apisecurityinaction.controller;

import org.dalesbred.Database;
import org.json.JSONObject;

import com.lambdaworks.crypto.SCryptUtil;

import spark.*;

public class SessionController {

    private final Database database;

    public SessionController(Database database) {
        this.database = database;
    }

    public JSONObject login(Request request, Response response) {
        var json = new JSONObject(request.body());
        var username = json.getString("username");
        var password = json.getString("password");

        var hash = database.findOptional(String.class,
                "SELECT pw_hash FROM users WHERE user_id = ?", username);

        if (hash.isPresent() &&
            SCryptUtil.check(password, hash.get())) {

            var session = request.session(false);
            if (session != null) {
                session.invalidate();
            }
            session = request.session(true);
            session.attribute("username", username);

            response.status(200);
            return new JSONObject();
        }
        throw new IllegalArgumentException(
                "invalid username or password");
    }

    public void validate(Request request, Response response) {
        var session = request.session(false);
        if (session == null) {
            return;
        }

        var username = session.attribute("username");
        if (username == null) {
            session.invalidate();
            return;
        }

        request.attribute("subject", username);
    }
}
