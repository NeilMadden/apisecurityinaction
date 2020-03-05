package com.manning.apisecurityinaction;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.nio.file.*;
import java.security.KeyStore;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.slf4j.*;

public class DtlsClient {
    private static final Logger logger = LoggerFactory.getLogger(DtlsClient.class);

    public static void main(String... args) throws Exception {
        try (var channel = new DtlsDatagramChannel(getClientContext());
             var in = Files.newBufferedReader(Paths.get("test.txt"))) {
            logger.info("Connecting to localhost:54321");
            channel.connect("localhost", 54321);

            String line;
            while ((line = in.readLine()) != null) {
                logger.info("Sending packet to server: {}", line);
                channel.send(line.getBytes(UTF_8));
            }

            logger.info("All packets sent");
            logger.info("Used cipher suite: {}",
                    channel.getSession().getCipherSuite());
        }
    }

    private static SSLContext getClientContext() throws Exception {
        var sslContext = SSLContext.getInstance("DTLS");

        var trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(new FileInputStream("as.example.com.ca.p12"),
                "changeit".toCharArray());

        var trustManagerFactory = TrustManagerFactory.getInstance(
                "PKIX");
        trustManagerFactory.init(trustStore);

        sslContext.init(null, trustManagerFactory.getTrustManagers(),
                null);
        return sslContext;
    }

}
