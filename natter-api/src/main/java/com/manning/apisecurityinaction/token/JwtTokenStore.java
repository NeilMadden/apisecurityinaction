package com.manning.apisecurityinaction.token;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import spark.Request;

import javax.crypto.SecretKey;
import java.text.ParseException;
import java.util.*;

public class JwtTokenStore implements SecureTokenStore {

    private final SecretKey encKey;

    public JwtTokenStore(SecretKey encKey) {
        this.encKey = encKey;
    }

    @Override
    public String create(Request request, Token token) {
        var claimsBuilder = new JWTClaimsSet.Builder()
                .subject(token.username)
                .audience("https://localhost:4567")
                .expirationTime(Date.from(token.expiry));
        token.attributes.forEach(claimsBuilder::claim);

        var header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
        var jwt = new EncryptedJWT(header, claimsBuilder.build());

        try {
            var encryptor = new DirectEncrypter(encKey);
            jwt.encrypt(encryptor);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return jwt.serialize();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var jwt = EncryptedJWT.parse(tokenId);

            var decryptor = new DirectDecrypter(encKey);
            jwt.decrypt(decryptor);

            var claims = jwt.getJWTClaimsSet();
            if (!claims.getAudience().contains("https://localhost:4567")) {
                return Optional.empty();
            }
            var expiry = claims.getExpirationTime().toInstant();
            var subject = claims.getSubject();
            var token = new Token(expiry, subject);
            var ignore = Set.of("exp", "sub", "aud");
            for (var attr : claims.getClaims().keySet()) {
                if (ignore.contains(attr)) continue;
                token.attributes.put(attr, claims.getStringClaim(attr));
            }

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
