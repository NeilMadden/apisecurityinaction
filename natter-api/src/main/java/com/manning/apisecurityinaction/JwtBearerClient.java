package com.manning.apisecurityinaction;

import java.io.FileInputStream;
import java.net.URI;
import java.net.http.*;
import java.security.KeyStore;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;

import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.SECONDS;

public class JwtBearerClient {

    public static void main(String... args) throws Exception {
        var password = "changeit".toCharArray();
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"),
                password);
        var privateKey = (ECPrivateKey) keyStore.getKey("es256-key",
                password);

        var jwk = ECKey.load(keyStore, "es256-key", password);
        System.out.println("JWK Set:");
        System.out.println(new JWKSet(jwk.toPublicJWK()));

        var clientId = "test";
        var as = "https://as.example.com/access_token";
        var header = new JWSHeader(JWSAlgorithm.ES256);
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
        System.out.println("Assertion: " + assertion);

        var form = "grant_type=client_credentials&scope=a+b+c" +
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
