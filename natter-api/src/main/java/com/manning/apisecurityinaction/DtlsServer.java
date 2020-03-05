package com.manning.apisecurityinaction;

import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.net.ssl.*;

import org.slf4j.*;

public class DtlsServer {
    private static final Logger logger = LoggerFactory.getLogger(DtlsServer.class);

    public static void main(String... args) throws Exception {
        try (var channel = new DtlsDatagramChannel(getServerContext())) {
            channel.bind(54321);
            logger.info("Listening on port 54321");

            var buffer = ByteBuffer.allocate(2048);

            while (true) {
                channel.receive(buffer);
                buffer.flip();
                var data = StandardCharsets.UTF_8.decode(buffer).toString();
                logger.info("Received: {}", data);
                buffer.compact();
            }
        } catch (ClosedChannelException e) {
            logger.info("Client disconnected");
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
