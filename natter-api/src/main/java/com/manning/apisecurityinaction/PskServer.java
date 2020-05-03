package com.manning.apisecurityinaction;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.dalesbred.Database;
import org.dalesbred.annotation.DalesbredInstantiator;
import org.h2.jdbcx.JdbcConnectionPool;
import software.pando.crypto.nacl.*;

import java.io.FileInputStream;
import java.net.*;
import java.security.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class PskServer {
    public static void main(String[] args) throws Exception {
        var psk = loadPsk(args[0].toCharArray());
        var encryptionKey = SecretBox.key();
        var deviceDb = createDatabase(encryptionKey, psk);
        var crypto = new BcTlsCrypto(new SecureRandom());
        var server = new PSKTlsServer(crypto, getIdentityManager(deviceDb, encryptionKey)) {
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return ProtocolVersion.DTLSv12.only();
            }
            @Override
            protected int[] getSupportedCipherSuites() {
                return new int[] {
                        CipherSuite.TLS_PSK_WITH_AES_128_CCM,
                        CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
                        CipherSuite.TLS_PSK_WITH_AES_256_CCM,
                        CipherSuite.TLS_PSK_WITH_AES_256_CCM_8,
                        CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
                };
            }
        };
        var buffer = new byte[2048];
        var serverSocket = new DatagramSocket(54321);
        var packet = new DatagramPacket(buffer, buffer.length);
        serverSocket.receive(packet);
        serverSocket.connect(packet.getSocketAddress());

        var protocol = new DTLSServerProtocol();
        var transport = new UDPTransport(serverSocket, 1500);
        var dtls = protocol.accept(server, transport);

        while (true) {
            var len = dtls.receive(buffer, 0, buffer.length, 60000);
            if (len == -1) break;
            var data = new String(buffer, 0, len, UTF_8);
            System.out.println("Received: " + data);
        }
    }

    static TlsPSKIdentityManager getIdentityManager(
            Database deviceDb, Key decryptionKey) {
        return new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() {
                return null;
            }

            @Override
            public byte[] getPSK(byte[] identity) {
                var device = deviceDb.findUnique(Device.class,
                        "SELECT device_id, psk_id, encrypted_psk " +
                                "FROM devices " +
                                "WHERE psk_id = ?", identity);
                System.out.println("Loaded PSK from client device: " + device.deviceId);
                return device.encryptedPsk.decrypt(decryptionKey);
            }
        };
    }

    static byte[] loadPsk(char[] password) throws Exception {
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"), password);
        return keyStore.getKey("aes-key", password).getEncoded();
    }

    static Database createDatabase(Key encryptionKey, byte[] exampleDevicePsk) {
        var pool = JdbcConnectionPool.create("jdbc:h2:mem:psk", "psk", "dummy");
        var database = Database.forDataSource(pool);
        database.update("CREATE TABLE devices(" +
                "device_id VARCHAR(255) PRIMARY KEY," +
                "psk_id BINARY(64) NOT NULL," +
                "encrypted_psk VARCHAR(1024) NOT NULL);");
        database.update("CREATE UNIQUE INDEX psk_id_idx ON devices(psk_id);");

        var encryptedPsk = SecretBox.encrypt(encryptionKey, exampleDevicePsk).toString();
        database.update("INSERT INTO devices(device_id, psk_id, encrypted_psk) VALUES (?, ?, ?)",
                "test", Crypto.hash(exampleDevicePsk), encryptedPsk);

        return database;
    }

    public static class Device {
        final String deviceId;
        final byte[] pskId;
        final SecretBox encryptedPsk;

        @DalesbredInstantiator
        public Device(String deviceId, byte[] pskId, String encryptedPsk) {
            this.deviceId = deviceId;
            this.pskId = pskId;
            this.encryptedPsk = SecretBox.fromString(encryptedPsk);
        }
    }
}
