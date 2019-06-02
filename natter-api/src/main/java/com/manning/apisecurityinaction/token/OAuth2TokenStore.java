package com.manning.apisecurityinaction.token;

import org.json.JSONObject;
import spark.Request;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class OAuth2TokenStore implements SecureTokenStore {

    private final URI introspectionEndpoint;
    private final String authorization;

    private final HttpClient httpClient;

    public OAuth2TokenStore(URI introspectionEndpoint,
                            String clientId, String clientSecret) {
        this.introspectionEndpoint = introspectionEndpoint;

        var credentials = URLEncoder.encode(clientId, UTF_8) + ":" +
                URLEncoder.encode(clientSecret, UTF_8);
        this.authorization = "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(UTF_8));

        this.httpClient = HttpClient.newHttpClient();
    }

    @Override
    public String create(Request request, Token token) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {

        var form = "token=" + URLEncoder.encode(tokenId, UTF_8);

        var httpRequest = HttpRequest.newBuilder()
                .uri(introspectionEndpoint)
                .header("Authorization", authorization)
                .POST(BodyPublishers.ofString(form))
                .build();

        try {
            var httpResponse = httpClient.send(httpRequest,
                    BodyHandlers.ofString());

            if (httpResponse.statusCode() == 200) {
                var json = new JSONObject(httpResponse.body());

                if (json.getBoolean("active")) {
                    return processResponse(json);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        return Optional.empty();
    }

    private Optional<Token> processResponse(JSONObject response) {
        var now = Instant.now();

        var defaultExpiry = now.plus(10, ChronoUnit.SECONDS);
        var expiry = Instant.ofEpochSecond(
                response.optLong("exp", defaultExpiry.getEpochSecond()));

        var subject = response.getString("sub");
        var token = new Token(expiry, subject);

        for (var attr : response.keySet()) {
            token.attributes.put(attr, response.optString(attr));
        }

        return Optional.of(token);
    }
}
