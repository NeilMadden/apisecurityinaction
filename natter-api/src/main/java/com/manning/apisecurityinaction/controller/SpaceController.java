package com.manning.apisecurityinaction.controller;

import java.sql.*;
import javax.sql.DataSource;
import org.json.JSONObject;
import spark.*;

public class SpaceController {

  private final DataSource datasource;

  public SpaceController(DataSource datasource) {
    this.datasource = datasource;
  }

  public JSONObject createSpace(Request request, Response response)
      throws SQLException {
    var json = new JSONObject(request.body());
    var spaceName = json.getString("name");
    var owner = json.getString("owner");

    try (var conn = datasource.getConnection();
         var stmt = conn.createStatement()) {
      conn.setAutoCommit(false);

      var spaceId = firstLong(stmt.executeQuery(
          "SELECT NEXT VALUE FOR space_id_seq;"));

      var insertStmt = conn.prepareStatement(
          "INSERT INTO spaces(space_id, name, owner) " +
              "VALUES(?, ?, ?);");
      insertStmt.setLong(1, spaceId);
      insertStmt.setString(2, spaceName);
      insertStmt.setString(3, owner);
      insertStmt.executeUpdate();
      conn.commit();

      response.status(201);
      response.header("Location", "/spaces/" + spaceId);

      return new JSONObject()
          .put("name", spaceName) .put("uri", "/spaces/" + spaceId);
    }
  }

  private static long firstLong(ResultSet resultSet)
      throws SQLException {
    if (!resultSet.next()) {
      throw new IllegalArgumentException("no results");
    }
    return resultSet.getLong(1);
  }
}