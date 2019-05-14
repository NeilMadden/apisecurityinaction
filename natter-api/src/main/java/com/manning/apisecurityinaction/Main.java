package com.manning.apisecurityinaction;

import static spark.Spark.*;

import java.nio.file.*;
import java.sql.Connection;
import java.util.Set;

import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.*;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.*;

import spark.*;

public class Main {

    public static void main(String... args) throws Exception {
        Spark.staticFiles.location("/public");
        secure("localhost.p12", "changeit", null, null);
        var datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter", "password");
        createTables(datasource.getConnection());
        datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter_api_user", "password");

        var database = Database.forDataSource(datasource);
        var spaceController = new SpaceController(database);
        var userController = new UserController(database);
        var sessionController = new SessionController(database);

        var rateLimiter = RateLimiter.create(2.0d);

        before((request, response) -> {
            if (!rateLimiter.tryAcquire()) {
                halt(429);
            }
        });

        before(new CorsFilter(Set.of("http://localhost:9999")));

        before(((request, response) -> {
            if (request.requestMethod().equals("POST") &&
            !"application/json".equals(request.contentType())) {
                halt(406, new JSONObject().put(
                    "error", "Only application/json supported"
                ).toString());
            }
        }));

        before((request, response) -> {
            var requestedWith = request.headers("X-Requested-With");
            if (requestedWith == null ||
            requestedWith.toLowerCase().startsWith("shockwaveflash")) {
                halt(403, new JSONObject().put(
                        "error", "Request must contain X-Requested-With header"
                ).toString());
            }
        });


        before(userController::authenticate);
        before(sessionController::validate);

        var auditController = new AuditController(database);
        before(auditController::auditRequestStart);
        afterAfter(auditController::auditRequestEnd);

        post("/sessions", sessionController::login);
        get("/logs", auditController::readAuditLog);

        post("/users", userController::registerUser);

        before("/spaces", userController::requireAuthentication);
        post("/spaces", spaceController::createSpace);

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

        afterAfter((request, response) -> {
            response.type("application/json");
            response.header("X-Content-Type-Options", "nosniff");
            response.header("X-XSS-Protection", "1; mode=block");
            response.header("Cache-Control", "private, max-age=0");
            response.header("Server", "");
        });

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

    private static void createTables(Connection connection) throws Exception {
        try (var conn = connection;
             var stmt = conn.createStatement()) {
            conn.setAutoCommit(false);
            Path path = Paths.get(
                    Main.class.getResource("/schema.sql").toURI());
            stmt.execute(Files.readString(path));
            conn.commit();
        }
    }
}