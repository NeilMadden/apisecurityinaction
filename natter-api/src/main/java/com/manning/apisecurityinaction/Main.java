package com.manning.apisecurityinaction;

import static spark.Spark.*;

import java.nio.file.*;

import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.*;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.*;
import com.manning.apisecurityinaction.token.*;

import spark.*;
import spark.embeddedserver.EmbeddedServers;
import spark.embeddedserver.jetty.EmbeddedJettyFactory;

public class Main {

    public static void main(String... args) throws Exception {
        EmbeddedServers.add(EmbeddedServers.defaultIdentifier(),
                new EmbeddedJettyFactory().withHttpOnly(true));
        Spark.staticFiles.location("/public");
        secure("localhost.p12", "changeit", null, null);
        var datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter", "password");
        var database = Database.forDataSource(datasource);
        createTables(database);
        datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter_api_user", "password");

        database = Database.forDataSource(datasource);
        var spaceController = new SpaceController(database);
        var userController = new UserController(database);
        var auditController = new AuditController(database);

        var rateLimiter = RateLimiter.create(2.0d);

        before((request, response) -> {
            if (!rateLimiter.tryAcquire()) {
                halt(429);
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

        TokenStore tokenStore = new CookieTokenStore();
        var tokenController = new TokenController(tokenStore);

        before(userController::authenticate);
        before(tokenController::validateToken);

        before(auditController::auditRequestStart);
        afterAfter(auditController::auditRequestEnd);

        before("/sessions", userController::requireAuthentication);
        post("/sessions", tokenController::login);
        delete("/sessions", tokenController::logout);

        before("/spaces", userController::requireAuthentication);
        post("/spaces", spaceController::createSpace);

        // Additional REST endpoints not covered in the book:

        before("/spaces/:spaceId/messages",
                userController.requirePermission("POST", "w"));
        post("/spaces/:spaceId/messages", spaceController::postMessage);

        before("/spaces/:spaceId/messages/*",
                userController.requirePermission("GET", "r"));
        get("/spaces/:spaceId/messages/:msgId",
            spaceController::readMessage);

        before("/spaces/:spaceId/messages",
                userController.requirePermission("GET", "r"));
        get("/spaces/:spaceId/messages", spaceController::findMessages);

        before("/spaces/:spaceId/members",
                userController.requirePermission("POST", "rwd"));
        post("/spaces/:spaceId/members", spaceController::addMember);

        var moderatorController =
            new ModeratorController(database);

        before("/spaces/:spaceId/messages/*",
                userController.requirePermission("DELETE", "d"));
        delete("/spaces/:spaceId/messages/:msgId",
            moderatorController::deletePost);

        get("/logs", auditController::readAuditLog);
        post("/users", userController::registerUser);

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