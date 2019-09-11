package com.manning.apisecurityinaction.token;

import java.net.*;
import java.text.ParseException;
import java.util.Optional;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import spark.Request;

public class SignedJwtAccessTokenStore implements SecureTokenStore {

    private final String expectedIssuer;
    private final String expectedAudience;
    private final JWSAlgorithm signatureAlgorithm;
    private final JWKSource<SecurityContext> jwkSource;

    public SignedJwtAccessTokenStore(String expectedIssuer,
                                     String expectedAudience,
                                     JWSAlgorithm signatureAlgorithm,
                                     URI jwkSetUri)
            throws MalformedURLException {
        this.expectedIssuer = expectedIssuer;
        this.expectedAudience = expectedAudience;
        this.signatureAlgorithm = signatureAlgorithm;
        this.jwkSource = new RemoteJWKSet<>(jwkSetUri.toURL());
    }

    @Override
    public String create(Request request, Token token) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void revoke(Request request, String tokenId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var verifier = new DefaultJWTProcessor<>();
            var keySelector = new JWSVerificationKeySelector<>(
                    signatureAlgorithm, jwkSource);
            verifier.setJWSKeySelector(keySelector);

            var claims = verifier.process(tokenId, null);

            if (!expectedIssuer.equals(claims.getIssuer())) {
                return Optional.empty();
            }
            if (!claims.getAudience().contains(expectedAudience)) {
                return Optional.empty();
            }

            var expiry = claims.getExpirationTime().toInstant();
            var subject = claims.getSubject();
            var token = new Token(expiry, subject);

            String scope;
            try {
                    scope = claims.getStringClaim("scope");
            } catch (ParseException e) {
                    scope = String.join(" ",
                    claims.getStringListClaim("scope"));
            }
            token.attributes.put("scope", scope);
            return Optional.of(token);

        } catch (ParseException | BadJOSEException | JOSEException e) {
            return Optional.empty();
        }
    }
}
