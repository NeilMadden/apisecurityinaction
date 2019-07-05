package com.manning.apisecurityinaction.controller;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import spark.*;

import java.text.ParseException;

public class IdTokenValidationFilter implements Filter {

    private final String expectedIssuer;
    private final String expectedAudience;
    private final JWSAlgorithm signatureAlgorithm;
    private final JWKSource<SecurityContext> jwkSource;

    public IdTokenValidationFilter(String expectedIssuer,
                                   String expectedAudience,
                                   JWSAlgorithm signatureAlgorithm,
                                   JWKSource<SecurityContext> jwkSource) {
        this.expectedIssuer = expectedIssuer;
        this.expectedAudience = expectedAudience;
        this.signatureAlgorithm = signatureAlgorithm;
        this.jwkSource = jwkSource;
    }

    @Override
    public void handle(Request request, Response response) {

        var idToken = request.headers("X-ID-Token");
        if (idToken == null) return;
        var subject = request.attribute("subject");
        if (subject == null) return;

        var verifier = new DefaultJWTProcessor<>();
        var keySelector = new JWSVerificationKeySelector<>(
                signatureAlgorithm, jwkSource);
        verifier.setJWSKeySelector(keySelector);

        try {
            var claims = verifier.process(idToken, null);

            if (!expectedIssuer.equals(claims.getIssuer())) {
                throw new IllegalArgumentException(
                        "invalid id token issuer");
            }
            if (!claims.getAudience().contains(expectedAudience)) {
                throw new IllegalArgumentException(
                        "invalid id token audience");
            }

            var client = request.attribute("client_id");
            var azp = claims.getStringClaim("azp");
            if (client != null && azp != null && !azp.equals(client)) {
                throw new IllegalArgumentException(
                        "client is not authorized party");
            }

            if (!subject.equals(claims.getSubject())) {
                throw new IllegalArgumentException(
                        "subject does not match id token");
            }

            request.attribute("id_token.claims", claims);

        } catch (ParseException | BadJOSEException | JOSEException e) {
            throw new IllegalArgumentException("invalid id token", e);
        }

    }
}
