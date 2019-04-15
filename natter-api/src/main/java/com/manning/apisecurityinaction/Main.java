package com.manning.apisecurityinaction;

import static spark.Spark.*;

import java.nio.file.*;
import java.sql.Connection;

import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.*;

import com.manning.apisecurityinaction.controller.SpaceController;

import spark.*;

public class Main {

    public static void main(String... args) throws Exception {
        var datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter", "password");
        createTables(datasource.getConnection());
        datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter_api_user", "password");

        var database = Database.forDataSource(datasource);
        var spaceController = new SpaceController(database);

        post("/spaces", spaceController::createSpace);
        afterAfter((request, response) -> {
            response.type("application/json");
        });

        internalServerError(new JSONObject()
            .put("error", "internal server error").toString());
        notFound(new JSONObject()
            .put("error", "not found").toString());

        exception(IllegalArgumentException.class, Main::badRequest);
        exception(JSONException.class, Main::badRequest);
    }

  private static void badRequest(Exception ex,
      Request request, Response response) {
    response.status(400);
    response.body("{\"error\": \"" + ex + "\"}");
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