package com.manning.apisecurityinaction;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.FileInputStream;
import java.net.*;
import java.security.*;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import software.pando.crypto.nacl.Crypto;

public class PskServer {
    public static void main(String[] args) throws Exception {
        var psk = loadPsk();
        var pskId = Crypto.hash(psk);

        var crypto = new BcTlsCrypto(new SecureRandom());
        var server = new PSKTlsServer(crypto, new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() {
                return pskId;
            }
            @Override
            public byte[] getPSK(byte[] identity) {
                return psk;
            }
        }) {
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return ProtocolVersion.DTLSv12.only();
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
            var data = new String(buffer, 0, len, UTF_8);
            System.out.println("Received: " + data);
        }
    }

    static byte[] loadPsk() throws Exception {
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"),
                "changeit".toCharArray());

        return keyStore.getKey("aes-key", "changeit".toCharArray()).getEncoded();
    }
}
