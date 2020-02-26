package com.manning.apisecurityinaction;

import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.security.KeyStore;

import javax.net.ssl.*;

public class UdpServer {
    static final int PACKET_SIZE = 1024;

    public static void main(String... args) throws Exception {
        try (var socket = new DTLSDatagramSocket(getSslContext(), 54321)) {
            System.out.printf("Listening on port %d%n",
                    socket.getLocalPort());

            var buffer = new byte[PACKET_SIZE];

            while (true) {
                var packet = new DatagramPacket(buffer, PACKET_SIZE);
                socket.receive(packet);
                System.out.printf("Received packet from %s - len: %d%n",
                        packet.getSocketAddress(), packet.getLength());
                var message = new String(buffer, 0, packet.getLength());
                System.out.println("Message: " + message);
            }
        }
    }

    private static SSLContext getSslContext() throws Exception {
        var sslContext = SSLContext.getInstance("DTLS");

        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("localhost.p12"),
                "changeit".toCharArray());

        var keyManager = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keyManager.init(keyStore, "changeit".toCharArray());

        sslContext.init(keyManager.getKeyManagers(), null, null);
        return sslContext;
    }
}
