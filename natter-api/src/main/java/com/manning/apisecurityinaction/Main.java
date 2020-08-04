package com.manning.apisecurityinaction;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.*;
import com.manning.apisecurityinaction.token.*;
import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.*;
import software.pando.crypto.nacl.Crypto;
import spark.*;

import java.io.FileInputStream;
import java.net.URI;
import java.nio.file.*;
import java.security.KeyStore;
import java.util.Set;

import static spark.Service.SPARK_DEFAULT_PORT;
import static spark.Spark.*;

public class Main {

    public static void main(String... args) throws Exception {
        Spark.staticFiles.location("/public");
        port(args.length > 0 ? Integer.parseInt(args[0])
                             : SPARK_DEFAULT_PORT);

        var secretsPath = Paths.get("/etc/secrets/database");
        var dbUsername = Files.readString(secretsPath.resolve("username"));
        var dbPassword = Files.readString(secretsPath.resolve("password"));

        var jdbcUrl = "jdbc:h2:tcp://natter-database-service:9092/mem:natter";
        var datasource = JdbcConnectionPool.create(
            jdbcUrl, dbUsername, dbPassword);
        var database = Database.forDataSource(datasource);
        createTables(database);
        datasource = JdbcConnectionPool.create(
            jdbcUrl, "natter_api_user", "password");

        database = Database.forDataSource(datasource);

        var keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("keystore.p12"),
                "changeit".toCharArray());
        var macKey = keystore.getKey("hmac-key", "changeit".toCharArray());

        // Examples of deriving keys using HKDF:
        // Derive a symmetric AES key
        var encKey = HKDF.expand(macKey, "token-encryption-key",
                32, "AES");

        // Derive an Ed25519 signature key pair
        var seed = HKDF.expand(macKey, "nacl-signing-key-seed",
                32, "NaCl");
        var keyPair = Crypto.seedSigningKeyPair(seed.getEncoded());

        SecureTokenStore tokenStore = HmacTokenStore.wrap(
                new DatabaseTokenStore(database), macKey);
        var capController = new CapabilityController(tokenStore);

        var introspectionEndpoint = URI.create(
                "http://as.example.com:8080/oauth2/instrospect");
        var oauthStore = new OAuth2TokenStore(introspectionEndpoint,
                "rs", "password");
        var tokenController = new TokenController(oauthStore);
        var spaceController = new SpaceController(database, capController);
        var userController = new UserController(database);
        var auditController = new AuditController(database);

        var rateLimiter = RateLimiter.create(2.0d);
        before((request, response) -> {
            if (!rateLimiter.tryAcquire()) {
                halt(429);
            }
        });
        before(new CorsFilter(Set.of("https://localhost:9999")));

        var expectedHostNames = Set.of(
                "api.natter.local",
                "api.natter.local:30567",
                "natter-api-service:4567",
                "natter-api-service.natter-api:4567",
                "natter-api-service.natter-api.svc.cluster.local:4567"
        );
        before((request, response) -> {
            if (!expectedHostNames.contains(request.host())) {
                halt(400);
            }
        });

        before(((request, response) -> {
            if (request.requestMethod().equals("POST") &&
            !"application/json".equals(request.contentType())) {
                halt(415, new JSONObject().put(
                    "error", "Only application/json supported"
                ).toString());
            }
        }));

        afterAfter((request, response) -> {
            response.type("application/json;charset=utf-8");
            response.header("X-Content-Type-Options", "nosniff");
            response.header("X-Frame-Options", "DENY");
            response.header("X-XSS-Protection", "0");
            response.header("Cache-Control", "no-store");
            response.header("Content-Security-Policy",
                    "default-src 'none'; frame-ancestors 'none'; sandbox");
            response.header("Server", "");
        });

        before(userController::authenticate);
        before(tokenController::validateToken);

        before(auditController::auditRequestStart);
        afterAfter(auditController::auditRequestEnd);

        var droolsController = new DroolsAccessController();
        before("/*", droolsController::enforcePolicy);

        before("/sessions", userController::requireAuthentication);
        before("/sessions",
                tokenController.requireScope("POST", "full_access"));
        post("/sessions", tokenController::login);
        delete("/sessions", tokenController::logout);

        before("/spaces", userController::requireAuthentication);
        before("/spaces",
                tokenController.requireScope("POST", "create_space"));
        post("/spaces", spaceController::createSpace);

        before("/spaces/:spaceId/messages", capController::lookupPermissions);
        before("/spaces/:spaceId/messages/*", capController::lookupPermissions);
        before("/spaces/:spaceId/members", capController::lookupPermissions);

        // Additional REST endpoints not covered in the book:
        before("/spaces/*/messages",
                tokenController.requireScope("POST", "post_message"));
        before("/spaces/:spaceId/messages",
                userController.requirePermission("POST", "w"));
        post("/spaces/:spaceId/messages", spaceController::postMessage);

        before("/spaces/*/messages/*",
                tokenController.requireScope("GET", "read_message"));
        before("/spaces/:spaceId/messages/*",
                userController.requirePermission("GET", "r"));
        get("/spaces/:spaceId/messages/:msgId",
            spaceController::readMessage);

        before("/spaces/*/messages",
                tokenController.requireScope("GET", "list_messages"));
        before("/spaces/:spaceId/messages",
                userController.requirePermission("GET", "r"));
        get("/spaces/:spaceId/messages", spaceController::findMessages);

        before("/spaces/*/members",
                tokenController.requireScope("POST", "add_member"));
        before("/spaces/:spaceId/members",
                userController.requirePermission("POST", "rwd"));
        post("/spaces/:spaceId/members", spaceController::addMember);

        var moderatorController =
            new ModeratorController(database);

        before("/spaces/*/messages/*",
                tokenController.requireScope("DELETE", "delete_message"));
        before("/spaces/:spaceId/messages/*",
                userController.requirePermission("DELETE", "d"));
        delete("/spaces/:spaceId/messages/:msgId",
            moderatorController::deletePost);

        get("/logs", auditController::readAuditLog);
        post("/users", userController::registerUser);

        post("/share", capController::share);

        internalServerError(new JSONObject()
            .put("error", "internal server error").toString());
        notFound(new JSONObject()
            .put("error", "not found").toString());

        exception(IllegalArgumentException.class, Main::badRequest);
        exception(JSONException.class, Main::badRequest);
        exception(EmptyResultException.class,
            (e, request, response) -> response.status(404));
    }

    private static void badRequest(Exception ex,
      Request request, Response response) {
        response.status(400);
        response.body(new JSONObject().put("error", ex.getMessage()).toString());
    }

    private static void createTables(Database database) throws Exception {
        var path = Paths.get(
                Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(path));
    }
}