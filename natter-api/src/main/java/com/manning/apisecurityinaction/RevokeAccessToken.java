package com.manning.apisecurityinaction;

import java.net.*;
import java.net.http.*;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RevokeAccessToken {

    private static final URI revocationEndpoint =
            URI.create("https://as.example.com:8443/oauth2/token/revoke");

    public static void main(String...args) throws Exception {

        if (args.length != 3) {
            throw new IllegalArgumentException(
                    "RevokeAccessToken clientId clientSecret token");
        }

        var clientId = args[0];
        var clientSecret = args[1];
        var token = args[2];

        var credentials = URLEncoder.encode(clientId, UTF_8) +

        ":" + URLEncoder.encode(clientSecret, UTF_8);
        var authorization = "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(UTF_8));

        var httpClient = HttpClient.newHttpClient();

        var form = "token=" + URLEncoder.encode(token, UTF_8) +
        "&token_type_hint=access_token";

        var httpRequest = HttpRequest.newBuilder()
                .uri(revocationEndpoint)
                .header("Content-Type",
                        "application/x-www-form-urlencoded")
                .header("Authorization", authorization)
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        httpClient.send(httpRequest, BodyHandlers.discarding());
    }
}
