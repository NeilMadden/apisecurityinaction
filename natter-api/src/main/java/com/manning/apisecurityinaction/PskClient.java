package com.manning.apisecurityinaction;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.net.*;
import java.nio.file.*;
import java.security.SecureRandom;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import software.pando.crypto.nacl.Crypto;

public class PskClient {
    public static void main(String[] args) throws Exception {
        var psk = PskServer.loadPsk(args[0].toCharArray());
        var pskId = Crypto.hash(psk);

        var crypto = new BcTlsCrypto(new SecureRandom());
        var client = new PSKTlsClient(crypto, pskId, psk) {
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return ProtocolVersion.DTLSv12.only();
            }

            @Override
            protected int[] getSupportedCipherSuites() {
                return new int[] {
                        CipherSuite.TLS_PSK_WITH_AES_128_CCM
                };
            }
        };

        var address = InetAddress.getByName("localhost");
        var socket = new DatagramSocket();
        socket.connect(address, 54321);
        socket.send(new DatagramPacket(new byte[0], 0));
        var transport = new UDPTransport(socket, 1500);
        var protocol = new DTLSClientProtocol();
        var dtls = protocol.connect(client, transport);

        try (var in = Files.newBufferedReader(Paths.get("test.txt"))) {
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println("Sending: " + line);
                var buf = line.getBytes(UTF_8);
                dtls.send(buf, 0, buf.length);
            }
        }
    }
}
