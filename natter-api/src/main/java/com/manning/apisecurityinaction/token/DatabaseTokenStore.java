package com.manning.apisecurityinaction.token;

import org.dalesbred.Database;
import org.json.JSONObject;
import org.slf4j.*;
import spark.Request;

import javax.crypto.Mac;
import java.io.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

public class DatabaseTokenStore implements TokenStore {
    private static final Logger logger =
            LoggerFactory.getLogger(DatabaseTokenStore.class);

    private final Database database;
    private final SecureRandom secureRandom;
    private final Key macKey;

    public DatabaseTokenStore(Database database, Key macKey) {
        this.database = database;
        this.macKey = macKey;
        this.secureRandom = new SecureRandom();

        Executors.newSingleThreadScheduledExecutor()
                .scheduleWithFixedDelay(this::deleteExpiredTokens,
                        10, 10, TimeUnit.MINUTES);
    }

    private String randomId() {
        var bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bytes);
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = randomId();
        var attrs = new JSONObject(token.attributes).toString();
        var tag = hmac(tokenId, token);

        database.updateUnique("INSERT INTO " +
            "tokens(token_id, user_id, expiry, attributes, mac_tag) " +
            "VALUES(?, ?, ?, ?, ?)", tokenId, token.username,
                token.expiry, attrs, tag);

        return tokenId;
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        return database.findOptional(row -> readToken(tokenId, row),
                "SELECT user_id, expiry, attributes, mac_tag " +
                "FROM tokens WHERE token_id = ?", tokenId);
    }

    private Token readToken(String tokenId, ResultSet resultSet)
            throws SQLException {
        var username = resultSet.getString(1);
        var expiry = resultSet.getTimestamp(2).toInstant();
        var json = new JSONObject(resultSet.getString(3));
        var tag = resultSet.getBytes(4);

        var token = new Token(expiry, username);
        for (var key : json.keySet()) {
            token.attributes.put(key, json.getString(key));
        }

        var computedTag = hmac(tokenId, token);
        if (!MessageDigest.isEqual(computedTag, tag)) {
            return null;
        }
        return token;
    }

    private void deleteExpiredTokens() {
        var deleted = database.update(
            "DELETE FROM tokens WHERE expiry < current_timestamp");
        logger.info("Deleted {} expired tokens", deleted);
    }

    private byte[] hmac(String tokenId, Token token) {
        try (var bytes = new ByteArrayOutputStream();
             var out = new DataOutputStream(bytes)) {

            out.writeUTF(tokenId);
            out.writeUTF(token.username);
            out.writeLong(token.expiry.toEpochMilli());

            var sortedAttrs = new TreeMap<>(token.attributes);
            out.writeUTF(sortedAttrs.toString());
            out.flush();

            var mac = Mac.getInstance(macKey.getAlgorithm());
            mac.init(macKey);
            return mac.doFinal(bytes.toByteArray());

        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
