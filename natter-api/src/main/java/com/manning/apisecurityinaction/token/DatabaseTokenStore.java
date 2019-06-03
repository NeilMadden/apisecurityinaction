package com.manning.apisecurityinaction.token;

import org.dalesbred.Database;
import org.dalesbred.annotation.DalesbredInstantiator;
import org.json.JSONObject;
import org.slf4j.*;
import spark.Request;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A version of the DatabaseTokenStore that uses encryption and
 * blind indexing to protect token data.
 */
public class DatabaseTokenStore implements TokenStore {
    private static final Logger logger =
            LoggerFactory.getLogger(DatabaseTokenStore.class);

    private final Database database;
    private final SecureRandom secureRandom;

    // The master encryption key used to encrypt and authenticate
    // data in the token database
    private final Key encryptionKey;
    // A HMAC key used to create a blind index to hide usernames
    // while still being searchable.
    private final Key blindIndexKey;

    public DatabaseTokenStore(Database database, Key encryptionKey,
                              Key blindIndexKey) {
        this.database = database;
        this.encryptionKey = encryptionKey;
        this.blindIndexKey = blindIndexKey;
        this.secureRandom = new SecureRandom();

        Executors.newSingleThreadScheduledExecutor()
                .scheduleAtFixedRate(this::deleteExpiredTokens,
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

        // Generate a random per-record key to encrypt the data.
        // This serves two purposes:
        // 1. When you change the master encryption key, you only
        // need to re-encrypt the per-record keys and not the entire
        // contents of the database.
        // 2. Because an AES-GCM key can only be used a relatively
        // small number of times, this ensures that a fresh key is
        // used for every record and so you do not need to worry about
        // GCM key usage limits.
        // (A much faster way to achieve point 2 is to use a KDF to
        // generate a unique key for each record).
        // For long-term storage of bulk data, key wrapping also
        // provides a fast way to securely delete that data: just
        // overwrite the encrypted key and the data is now completely
        // unrecoverable.
        var recordKey = randomKey();
        var encryptedKey = wrapKey(recordKey);

        // Now you can encrypt the attributes using the record key
        var attrs = encryptAttributes(recordKey, tokenId, token);

        // To obscure the username, while still allowing it to be
        // queried, you can use a blind index. Rather than storing
        // the username directly you store HMAC-SHA256(key, username).
        // An attacker that gains read access to the database will
        // not be able to read the usernames, but we can still do
        // (exact) equality searches on them. However, be aware that
        // a blind index does leak some information about the username
        // as it will have the same value every time that user creates
        // a token. A patient attacker may be able to use this information
        // to decode all the usernames by watching the database over
        // a long period of time.
        var obscuredUsername = blindIndex(token.username);

        // Insert the encrypted data and the wrapped key
        database.updateUnique("INSERT INTO " +
            "tokens(token_id, user_id, expiry, attributes, record_key) " +
            "VALUES(?, ?, ?, ?, ?)", tokenId,
                obscuredUsername,
                token.expiry, attrs, encryptedKey);

        return tokenId;
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        return database.findOptional(this::readToken,
                "SELECT user_id, expiry, attributes, token_id, record_key " +
                "FROM tokens WHERE token_id = ?", tokenId);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        database.update("DELETE FROM tokens WHERE token_id = ?",
                tokenId);
    }

    public void revokeAllTokensForUser(String username) {
        // An example method using the blind index
        database.update("DELETE FROM tokens WHERE username = ?",
                blindIndex(username));
    }

    private Token readToken(ResultSet resultSet)
            throws SQLException {
        var username = resultSet.getString(1);
        var expiry = resultSet.getTimestamp(2).toInstant();
        // Read the encrypted attributes and the encrypted key
        var encryptedAttrs = resultSet.getString(3);
        var tokenId = resultSet.getString(4);
        var encryptedKey = resultSet.getBytes(5);

        // Unwrap the key to reveal the per-record key
        var recordKey = unwrapKey(encryptedKey);
        var token = new Token(expiry, username);
        // Use the per-record key to decrypt the rest of the attributes
        var json = decryptAttributes(recordKey, tokenId, token,
                encryptedAttrs);

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

    private String encryptAttributes(Key recordKey,
                                     String tokenId, Token token) {
        try {
            // AES-GCM is a fast authenticated encryption cipher.
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            // It takes a random 12-byte nonce for each message
            // Although you could use a fixed nonce here as we are
            // generating a unique key for each record, it is safer
            // to always use a random nonce just in case.
            var nonce = new byte[12];
            secureRandom.nextBytes(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, recordKey,
                    new GCMParameterSpec(128, nonce));

            // Include other attributes of the token as "associated data".
            // These attributes will be authenticated but not encrypted,
            // ensuring that they cannot be tampered with. By including
            // the tokenId in the calculation, you ensure that the
            // encrypted attributes cannot be copy and pasted from
            // one token to another, which would otherwise be possible.
            cipher.updateAAD(associatedData(tokenId, token));

            var plaintext = new JSONObject(token.attributes).toString();
            var ciphertext = cipher.doFinal(plaintext.getBytes(UTF_8));

            var encoder = Base64.getUrlEncoder().withoutPadding();
            return encoder.encodeToString(nonce) + '.' +
                    encoder.encodeToString(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private JSONObject decryptAttributes(Key recordKey,
                                         String tokenId, Token token,
                                         String encryptedAttrs) {
        var index = encryptedAttrs.indexOf('.');
        if (index == -1) throw new IllegalArgumentException("invalid token");
        var decoder = Base64.getUrlDecoder();
        var nonce = decoder.decode(encryptedAttrs.substring(0, index));
        var ciphertext = decoder.decode(encryptedAttrs.substring(index + 1));

        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, recordKey,
                    new GCMParameterSpec(128, nonce));

            // When decrypting you must include the same associated
            // data that was used for encryption, otherwise it will
            // fail to validate.
            cipher.updateAAD(associatedData(tokenId, token));
            var plaintext = cipher.doFinal(ciphertext);

            return new JSONObject(new String(plaintext, UTF_8));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] associatedData(String tokenId, Token token) {
        // Any unambiguous encoding of the associated data will do.
        // Here we use JSON for simplicity.
        return new JSONObject()
                .put("tokenId", tokenId)
                .put("username", token.username)
                .put("expiry", token.expiry.getEpochSecond())
                .toString()
                .getBytes(UTF_8);
    }

    private Key randomKey() {
        var keyData = new byte[32];
        secureRandom.nextBytes(keyData);
        return new SecretKeySpec(keyData, "AES");
    }

    private byte[] wrapKey(Key recordKey) {
        return wrapKey(encryptionKey, recordKey);
    }

    private byte[] wrapKey(Key masterKey, Key recordKey) {
        try {
            // For key wrapping you can use the dedicated AESWrap
            // deterministic encryption mode. A better alternative
            // is AES-SIV mode, but this is not standard in Java.
            var cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.WRAP_MODE, masterKey);
            return cipher.wrap(recordKey);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private Key unwrapKey(byte[] wrappedKey) {
        try {
            var cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.UNWRAP_MODE, encryptionKey);
            return cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private String blindIndex(String username) {
        try {
            var mac = Mac.getInstance(blindIndexKey.getAlgorithm());
            mac.init(blindIndexKey);
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(username.getBytes(UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * A sketch of how to implement master encryption key rotation.
     * For tokens this is probably not worth it, and you can keep
     * around the original key until the old tokens expire. But for
     * larger data that is long-lived, it can be useful to be able
     * to re-encrypt the per-record keys rather than having to
     * re-encrypt the entire database.
     *
     * @param newKey the new encryption key.
     */
    public void rotateMasterKey(Key newKey) {
        for (var key : database.findAll(EncryptedKey.class,
                "SELECT token_id, record_key FROM tokens")) {

            var unwrapped = unwrapKey(key.encryptedKey);
            var rewrapped = wrapKey(newKey, unwrapped);

            database.updateUnique("UPDATE tokens " +
                    "SET record_key = ? " +
                    "WHERE token_id = ?", rewrapped, key.tokenId);
        }
    }

    static class EncryptedKey {
        final String tokenId;
        final byte[] encryptedKey;

        @DalesbredInstantiator
        EncryptedKey(String tokenId, byte[] encryptedKey) {
            this.tokenId = tokenId;
            this.encryptedKey = encryptedKey;
        }
    }
}
