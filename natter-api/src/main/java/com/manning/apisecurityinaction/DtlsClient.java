package com.manning.apisecurityinaction;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.FileInputStream;
import java.nio.file.*;
import java.security.KeyStore;

import javax.net.ssl.*;

import org.slf4j.*;

public class DtlsClient {
    private static final Logger logger = LoggerFactory.getLogger(DtlsClient.class);

    public static void main(String... args) throws Exception {
        try (var channel = new DtlsDatagramChannel(getClientContext(), sslParameters());
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

    private static SSLParameters sslParameters() {
        var params = DtlsDatagramChannel.defaultSslParameters();
        params.setCipherSuites(new String[] {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
        });
        return params;
    }

}
