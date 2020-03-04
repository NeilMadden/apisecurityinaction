package com.manning.apisecurityinaction;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;

public class DtlsServer {
    static final int PACKET_SIZE = 1024;

    public static void main(String... args) throws Exception {
        try (var channel = new DtlsDatagramChannel(
                getServerContext(), DtlsClient.sslParameters())) {
            channel.bind(54321);
            System.out.println("Listening on port 54321");

            var buffer = ByteBuffer.allocate(PACKET_SIZE);

            while (true) {
                channel.receive(buffer);
                buffer.flip();
                var data = buffer.asCharBuffer().toString();
                System.out.println("Data: " + data);
                buffer.compact();
            }
        }
    }

    private static SSLContext getServerContext() throws Exception {
        var sslContext = SSLContext.getInstance("DTLS");

        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("localhost.p12"),
                "changeit".toCharArray());

        var keyManager = KeyManagerFactory.getInstance("PKIX");
        keyManager.init(keyStore, "changeit".toCharArray());

        sslContext.init(keyManager.getKeyManagers(), null, null);
        return sslContext;
    }
}
