package com.manning.apisecurityinaction;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.FileInputStream;
import java.net.*;
import java.nio.file.*;
import java.security.KeyStore;

import javax.net.ssl.*;

public class UdpClient {
    public static void main(String... args) throws Exception {
        var serverAddr = new InetSocketAddress("localhost", 54321);

        try (var socket = new DTLSDatagramSocket(getSslContext());
             var in = Files.newBufferedReader(Paths.get("test.txt"))) {
            var buffer = new byte[UdpServer.PACKET_SIZE];
            var packet = new DatagramPacket(buffer, buffer.length);
            packet.setSocketAddress(serverAddr);

            String line;
            while ((line = in.readLine()) != null) {
                System.out.println("Sending packet to server");
                packet.setData(line.getBytes(UTF_8));
                socket.send(packet);
            }

            System.out.println("All packets sent");
        }
    }

    private static SSLContext getSslContext() throws Exception {
        var sslContext = SSLContext.getInstance("DTLS");

        var trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(new FileInputStream("localhost.p12"),
                "changeit".toCharArray());

        var trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
        return sslContext;
    }
}
