package com.manning.apisecurityinaction;

import org.dalesbred.Database;
import org.dalesbred.annotation.DalesbredInstantiator;
import org.h2.jdbcx.JdbcConnectionPool;
import software.pando.crypto.nacl.SecretBox;

import java.io.*;
import java.security.Key;
import java.util.Optional;

public class Device {
    final String deviceId;
    final String manufacturer;
    final String model;
    final byte[] encryptedPsk;

    @DalesbredInstantiator
    public Device(String deviceId, String manufacturer,
                  String model, byte[] encryptedPsk) {
        this.deviceId = deviceId;
        this.manufacturer = manufacturer;
        this.model = model;
        this.encryptedPsk = encryptedPsk;
    }

    public byte[] getPsk(Key decryptionKey) {
        try (var in = new ByteArrayInputStream(encryptedPsk)) {
            var box = SecretBox.readFrom(in);
            return box.decrypt(decryptionKey);
        } catch (IOException e) {
            throw new RuntimeException("Unable to decrypt PSK", e);
        }
    }

    static Database createDatabase(SecretBox encryptedPsk) throws IOException {
        var pool = JdbcConnectionPool.create("jdbc:h2:mem:devices",
                "devices", "password");
        var database = Database.forDataSource(pool);

        database.update("CREATE TABLE devices(" +
                "device_id VARCHAR(30) PRIMARY KEY," +
                "manufacturer VARCHAR(100) NOT NULL," +
                "model VARCHAR(100) NOT NULL," +
                "encrypted_psk VARBINARY(1024) NOT NULL)");

        var out = new ByteArrayOutputStream();
        encryptedPsk.writeTo(out);
        database.update("INSERT INTO devices(" +
                "device_id, manufacturer, model, encrypted_psk) " +
                "VALUES(?, ?, ?, ?)", "test", "example", "ex001",
                out.toByteArray());

        return database;
    }

    static Optional<Device> find(Database database, String deviceId) {
        return database.findOptional(Device.class,
                "SELECT device_id, manufacturer, model, encrypted_psk " +
                        "FROM devices WHERE device_id = ?", deviceId);
    }
}
