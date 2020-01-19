package com.manning.apisecurityinaction.token;

import java.text.ParseException;
import java.util.*;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import spark.Request;

public class SignedJwtTokenStore implements AuthenticatedTokenStore {
    private final JWSSigner signer;
    private final JWSVerifier verifier;
    private final JWSAlgorithm algorithm;
    private final String audience;

    public SignedJwtTokenStore(JWSSigner signer,
               JWSVerifier verifier, JWSAlgorithm algorithm,
               String audience) {
        this.signer = signer;
        this.verifier = verifier;
        this.algorithm = algorithm;
        this.audience = audience;
    }

    @Override
    public String create(Request request, Token token) {
        var claimsSet = new JWTClaimsSet.Builder()
                .subject(token.username)
                .audience(audience)
                .expirationTime(Date.from(token.expiry))
                .claim("attrs", token.attributes)
                .build();
        var header = new JWSHeader(algorithm);
        var jwt = new SignedJWT(header, claimsSet);
        try {
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var jwt = SignedJWT.parse(tokenId);
            if (!jwt.verify(verifier)) {
                throw new JOSEException("Invalid signature");
            }

            var claims = jwt.getJWTClaimsSet();
            if (!claims.getAudience().contains(audience)) {
                throw new JOSEException("Incorrect audience");
            }

            var expiry = claims.getExpirationTime().toInstant();
            var subject = claims.getSubject();
            var token = new Token(expiry, subject);
            var attrs = claims.getJSONObjectClaim("attrs");
            attrs.forEach((key, value) ->
                    token.attributes.put(key, (String) value));

            return Optional.of(token);
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {
        // TODO
    }
}
