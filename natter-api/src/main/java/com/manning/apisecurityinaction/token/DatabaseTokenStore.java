package com.manning.apisecurityinaction.token;

import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

import org.dalesbred.Database;
import org.json.JSONObject;
import org.slf4j.*;
import spark.Request;

import static com.manning.apisecurityinaction.token.CookieTokenStore.sha256;

public class DatabaseTokenStore implements TokenStore {
    private static final Logger logger =
            LoggerFactory.getLogger(DatabaseTokenStore.class);

    private final Base64.Encoder encoder =
            Base64.getUrlEncoder().withoutPadding();
    private final Database database;
    private final SecureRandom secureRandom;

    public DatabaseTokenStore(Database database) {
        this.database = database;
        this.secureRandom = new SecureRandom();

        Executors.newSingleThreadScheduledExecutor()
                .scheduleAtFixedRate(this::deleteExpiredTokens,
                        10, 10, TimeUnit.MINUTES);
    }

    private String randomId() {
        var bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        return encoder.encodeToString(bytes);
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = randomId();
        var attrs = new JSONObject(token.attributes).toString();

        database.updateUnique("INSERT INTO " +
            "tokens(token_id, user_id, expiry, attributes) " +
            "VALUES(?, ?, ?, ?)", hash(tokenId), token.username,
                token.expiry, attrs);

        return tokenId;
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        return database.findOptional(this::readToken,
                "SELECT user_id, expiry, attributes " +
                "FROM tokens WHERE token_id = ?", hash(tokenId));
    }

    @Override
    public void revoke(Request request, String tokenId) {
        database.update("DELETE FROM tokens WHERE token_id = ?",
                hash(tokenId));
    }

    private String hash(String tokenId) {
        var hash = sha256(tokenId);
        return encoder.encodeToString(hash);
    }

    private Token readToken(ResultSet resultSet)
            throws SQLException {
        var username = resultSet.getString(1);
        var expiry = resultSet.getTimestamp(2).toInstant();
        var json = new JSONObject(resultSet.getString(3));

        var token = new Token(expiry, username);
        for (var key : json.keySet()) {
            token.attributes.put(key, json.getString(key));
        }
        return token;
    }

    private void deleteExpiredTokens() {
        var deleted = database.update(
            "DELETE FROM tokens WHERE expiry < current_timestamp");
        logger.info("Deleted {} expired tokens", deleted);
    }
}
