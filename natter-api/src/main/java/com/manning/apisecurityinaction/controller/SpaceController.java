package com.manning.apisecurityinaction.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

import org.dalesbred.Database;
import org.json.*;

import spark.*;

public class SpaceController {

  private final Database database;

  public SpaceController(Database database) {
    this.database = database;
  }

  public JSONObject createSpace(Request request, Response response) {
    var json = new JSONObject(request.body());
    var spaceName = json.getString("name");
    if (spaceName.length() > 255) {
      throw new IllegalArgumentException("space name too long");
    }
    var owner = json.getString("owner");
    if (!owner.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")) {
      throw new IllegalArgumentException("invalid username");
    }

    return database.withTransaction(tx -> {
      var spaceId = database.findUniqueLong(
          "SELECT NEXT VALUE FOR space_id_seq;");

      database.updateUnique(
          "INSERT INTO spaces(space_id, name, owner) " +
              "VALUES(?, ?, ?);", spaceId, spaceName, owner);

      response.status(201);
      response.header("Location", "/spaces/" + spaceId);

      return new JSONObject()
          .put("name", spaceName) .put("uri", "/spaces/" + spaceId);

    });
  }

  // Additional REST API endpoints not covered in the book:
  public JSONObject postMessage(Request request, Response response) {
    var spaceId = Long.parseLong(request.params(":spaceId"));
    var json = new JSONObject(request.body());
    var user = json.getString("author");
    if (!user.matches("[a-zA-Z][a-zA-Z0-9]{0,29}")) {
      throw new IllegalArgumentException("invalid username");
    }
    var message = json.getString("message");
    if (message.length() > 1024) {
      throw new IllegalArgumentException("message is too long");
    }

    return database.withTransaction(tx -> {
      var msgId = database.findUniqueLong(
          "SELECT NEXT VALUE FOR msg_id_seq;");
      database.updateUnique(
          "INSERT INTO messages(space_id, msg_id, msg_time," +
              "author, msg_text) " +
              "VALUES(?, ?, current_timestamp, ?, ?)",
          spaceId, msgId, user, message);

      response.status(201);
      var uri = "/spaces/" + spaceId + "/messages/" + msgId;
      response.header("Location", uri);
      return new JSONObject().put("uri", uri);
    });
  }

  public Message readMessage(Request request, Response response) {
    var spaceId = Long.parseLong(request.params(":spaceId"));
    var msgId = Long.parseLong(request.params(":msgId"));

    var message = database.findUnique(Message.class,
        "SELECT space_id, msg_id, author, msg_time, msg_text " +
            "FROM messages WHERE msg_id = ? AND space_id = ?",
        msgId, spaceId);

    response.status(200);
    return message;
  }

  public JSONArray findMessages(Request request, Response response) {
    var since = Instant.now().minus(1, ChronoUnit.DAYS);
    if (request.queryParams("since") != null) {
      since = Instant.parse(request.queryParams("since"));
    }
    var spaceId = Long.parseLong(request.params(":spaceId"));

    var messages = database.findAll(Long.class,
        "SELECT msg_id FROM messages " +
            "WHERE space_id = ? AND msg_time >= ?;",
        spaceId, since);

    response.status(200);
    return new JSONArray(messages.stream()
        .map(msgId -> "/spaces/" + spaceId + "/messages/" + msgId)
        .collect(Collectors.toList()));
  }

  public static class Message {
    private final long spaceId;
    private final long msgId;
    private final String author;
    private final Instant time;
    private final String message;

    public Message(long spaceId, long msgId, String author,
        Instant time, String message) {
      this.spaceId = spaceId;
      this.msgId = msgId;
      this.author = author;
      this.time = time;
      this.message = message;
    }
    @Override
    public String toString() {
      JSONObject msg = new JSONObject();
      msg.put("uri",
          "/spaces/" + spaceId + "/messages/" + msgId);
      msg.put("author", author);
      msg.put("time", time.toString());
      msg.put("message", message);
      return msg.toString();
    }
  }
}