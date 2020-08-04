package com.manning.apisecurityinaction;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.*;

import java.io.FileInputStream;
import java.net.URI;
import java.net.http.*;
import java.security.KeyStore;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.SECONDS;
import static spark.Spark.*;

public class JwtBearerClient {

    public static void main(String... args) throws Exception {
        var password = "changeit".toCharArray();
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"),
                password);
        var privateKey = (ECPrivateKey)
                keyStore.getKey("es256-key", password);

        var jwkSet = JWKSet.load(keyStore, alias -> password)
                .toPublicJWKSet();

        secure("localhost.p12", "changeit", null, null);
        get("/jwks", (request, response) -> {
            response.type("application/jwk-set+json");
            return jwkSet.toString();
        });

        var clientId = "test";
        var as = "http://as.example.com:8080/oauth2/access_token";
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID("es256-key")
                .build();
        var claims = new JWTClaimsSet.Builder()
                .subject(clientId)
                .issuer(clientId)
                .expirationTime(Date.from(now().plus(30, SECONDS)))
                .audience(as)
                .jwtID(UUID.randomUUID().toString())
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(privateKey));
        var assertion = jwt.serialize();

        var form = "grant_type=client_credentials&scope=create_space" +
                "&client_assertion_type=" +
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" +
                "&client_assertion=" + assertion;

        var httpClient = HttpClient.newHttpClient();
        var request = HttpRequest.newBuilder()
                .uri(URI.create(as))
                .header("Content-Type",
                        "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        var response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());
        System.out.println(response.statusCode());
        System.out.println(response.body());
    }
}
