package com.manning.apisecurityinaction;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.nio.file.*;
import java.security.KeyStore;

import static java.nio.charset.StandardCharsets.UTF_8;

public class DtlsClient {
    public static void main(String... args) throws Exception {

        try (var channel = new DtlsDatagramChannel(getClientContext(), sslParameters());
             var in = Files.newBufferedReader(Paths.get("test.txt"))) {
            channel.connect("localhost", 54321);

            String line;
            while ((line = in.readLine()) != null) {
                System.out.println("Sending packet to server");
                channel.send(line.getBytes(UTF_8));
            }

            System.out.println("All packets sent");
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

    static SSLParameters sslParameters() {
        var params = new SSLParameters();
        params.setProtocols(new String[] { "DTLSv1.2" });
        params.setMaximumPacketSize(1500);
        params.setEnableRetransmissions(true);
        params.setEndpointIdentificationAlgorithm("HTTPS");
        return params;
    }
}
