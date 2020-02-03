package com.manning.apisecurityinaction.controller;

import java.io.*;
import java.net.URLDecoder;
import java.security.cert.*;
import java.util.Base64;

import com.lambdaworks.crypto.SCryptUtil;
import org.dalesbred.Database;
import org.dalesbred.query.QueryBuilder;
import org.json.JSONObject;
import spark.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static spark.Spark.halt;

public class UserController {
    private static final String USERNAME_PATTERN =
            "[a-zA-Z][a-zA-Z0-9]{1,29}";
    private static final int DNS_TYPE = 2;

    private final Database database;

    public UserController(Database database) {
        this.database = database;
    }

    public JSONObject registerUser(Request request,
            Response response) throws Exception {
        var json = new JSONObject(request.body());
        var username = json.getString("username");
        var password = json.optString("password", null);

        if (!username.matches(USERNAME_PATTERN)) {
            throw new IllegalArgumentException("invalid username");
        }

        String hash = null;
        if (password != null) {
            if (password.length() < 8) {
                throw new IllegalArgumentException(
                        "password must be at least 8 characters");
            }

            hash = SCryptUtil.scrypt(password, 32768, 8, 1);
        }
        database.updateUnique(
                "INSERT INTO users(user_id, pw_hash)" +
                        " VALUES(?, ?)", username, hash);

        response.status(201);
        response.header("Location", "/users/" + username);
        return new JSONObject().put("username", username);
    }

    public void authenticate(Request request, Response response) {
        if ("SUCCESS".equals(request.headers("ssl-client-verify"))) {
            processClientCertificateAuth(request);
            return;
        }
        var credentials = getCredentials(request);
        if (credentials == null) return;

        var username = credentials[0];
        var password = credentials[1];

        var hash = database.findOptional(String.class,
                "SELECT pw_hash FROM users WHERE user_id = ?", username);

        if (hash.isPresent() && SCryptUtil.check(password, hash.get())) {
            request.attribute("subject", username);

            var groups = database.findAll(String.class,
                "SELECT DISTINCT group_id FROM group_members " +
                        "WHERE user_id = ?", username);
            request.attribute("groups", groups);
        }
    }

    void processClientCertificateAuth(Request request) {
        var pem = request.headers("ssl-client-cert");
        var cert = decodeCert(pem);
        try {
            if (cert.getSubjectAlternativeNames() == null) {
                return;
            }
            for (var san : cert.getSubjectAlternativeNames()) {
                if ((Integer) san.get(0) == DNS_TYPE) {
                    var subject = (String) san.get(1);
                    request.attribute("subject", subject);
                    return;
                }
            }
        } catch (CertificateParsingException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate decodeCert(String encodedCert) {
        var pem = URLDecoder.decode(encodedCert, UTF_8);
        try (var in = new ByteArrayInputStream(pem.getBytes(UTF_8))) {
            var certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    String[] getCredentials(Request request) {
        var authHeader = request.headers("Authorization");
        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            return null;
        }

        var offset = "Basic ".length();
        var credentials = new String(Base64.getDecoder().decode(
                authHeader.substring(offset)), UTF_8);

        var components = credentials.split(":", 2);
        if (components.length != 2) {
            throw new IllegalArgumentException("invalid auth header");
        }

        var username = components[0];
        if (!username.matches(USERNAME_PATTERN)) {
            throw new IllegalArgumentException("invalid username");
        }

        return components;
    }

    public void requireAuthentication(Request request, Response response) {
        if (request.attribute("subject") == null) {
            response.header("WWW-Authenticate", "Bearer");
            halt(401);
        }
    }

    public void lookupPermissions(Request request, Response response) {
        requireAuthentication(request, response);
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var username = (String) request.attribute("subject");

        var query = new QueryBuilder(
                "SELECT rp.perms " +
                        "  FROM role_permissions rp JOIN user_roles ur" +
                        "    ON rp.role_id = ur.role_id" +
                        " WHERE ur.space_id = ? AND ur.user_id = ?",
                spaceId, username);

        var role = (String) request.attribute("role");
        if (role != null) {
            query.append(" AND ur.role_id = ?", role);
        }

        var perms = String.join("",
                database.findAll(String.class, query.build()));
        request.attribute("perms", perms);
    }

    public Filter requirePermission(String method, String permission) {
        return (request, response) -> {
            if (!method.equals(request.requestMethod())) {
                return;
            }

            var perms = request.<String>attribute("perms");
            if (perms == null || !perms.contains(permission)) {
                halt(403);
            }
        };
    }
}
