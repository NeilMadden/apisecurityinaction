package com.manning.apisecurityinaction;

import static java.nio.charset.StandardCharsets.UTF_8;
import static spark.Spark.halt;

import java.security.*;
import java.util.*;

import org.json.JSONObject;

import spark.*;

public class CsrfFilter implements Filter {
    private static final String HEADER = "X-CSRF-Token";
    private static final Base64.Decoder DECODER =
            Base64.getUrlDecoder();
    private static final Set<String> SAFE_METHODS =
      Set.of("GET", "HEAD", "OPTIONS");
    @Override
    public void handle(Request request, Response response) {

        if (SAFE_METHODS.contains(request.requestMethod())) {
            return;
        }

        var session = request.session(false);
        if (session == null) {
            return;
        }

        var csrfToken = request.headers(HEADER);

        if (!validate(session, csrfToken)) {
            halt(401, new JSONObject().put(
                    "error", "Missing " + HEADER + " header"
            ).toString());
        }
    }

    public static boolean validate(Session session, String csrfToken) {
        var expected = hash(session.id());
        var provided = csrfToken == null ? null : DECODER.decode(csrfToken);

        return MessageDigest.isEqual(expected, provided);
    }

    public static byte[] hash(String cookie) {
        try {
            var hashFunction = MessageDigest.getInstance("SHA-256");
            return hashFunction.digest(cookie.getBytes(UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
