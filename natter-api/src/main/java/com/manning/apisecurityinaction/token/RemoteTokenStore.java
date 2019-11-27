package com.manning.apisecurityinaction.token;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Optional;

import org.json.JSONObject;
import spark.Request;

public class RemoteTokenStore implements SecureTokenStore {

    private final URI tokenServiceUri;
    private final HttpClient httpClient;

    public RemoteTokenStore(String tokenServiceUri) {
        this.tokenServiceUri = URI.create(tokenServiceUri);
        this.httpClient = HttpClient.newBuilder().build();
    }

    @Override
    public String create(Request request, Token token) {
        var json = token.toJson();
        var httpRequest = HttpRequest.newBuilder(tokenServiceUri)
                .POST(BodyPublishers.ofString(json.toString()))
                .build();

        return send(httpRequest).getString("tokenId");
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var httpRequest = HttpRequest.newBuilder()
                .uri(tokenServiceUri.resolve("/tokens/" + tokenId))
                .GET()
                .build();

        try {
            var tokenJson = send(httpRequest);
            var token = Token.fromJson(tokenJson);
            return Optional.of(token);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var httpRequest = HttpRequest.newBuilder()
                .uri(tokenServiceUri.resolve("/tokens/" + tokenId))
                .DELETE()
                .build();

        send(httpRequest);
    }

    private JSONObject send(HttpRequest request) {
        try {
            var response = httpClient.send(request,
                    BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw new RuntimeException(
                        "Bad response from token service: "
                                + response.statusCode());
            }
            return new JSONObject(response.body());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }
}
