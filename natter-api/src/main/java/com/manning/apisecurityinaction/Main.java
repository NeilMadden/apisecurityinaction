package com.manning.apisecurityinaction;

import static spark.Spark.*;

import java.nio.file.*;
import java.sql.Connection;

import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONObject;

import com.manning.apisecurityinaction.controller.SpaceController;

public class Main {

    public static void main(String... args) throws Exception {
        var datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter", "password");
        createTables(datasource.getConnection());

        var spaceController =
            new SpaceController(datasource);

        post("/spaces", spaceController::createSpace);
        afterAfter((request, response) -> {
            response.type("application/json");
        });

        internalServerError(new JSONObject()
            .put("error", "internal server error").toString());
        notFound(new JSONObject()
            .put("error", "not found").toString());
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