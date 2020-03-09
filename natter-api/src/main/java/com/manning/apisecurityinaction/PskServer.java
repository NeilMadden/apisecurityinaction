package com.manning.apisecurityinaction;

import java.io.*;
import java.net.ServerSocket;
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
            protected int[] getSupportedCipherSuites() {
                return new int[] {
                        CipherSuite.TLS_PSK_WITH_AES_128_CCM
                };
            }
        };

        var serverSocket = new ServerSocket(54321);
        var socket = serverSocket.accept();
        var protocol = new TlsServerProtocol(
                socket.getInputStream(), socket.getOutputStream());
        protocol.accept(server);

        try (var in = new BufferedReader(new InputStreamReader(protocol.getInputStream()))) {
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println("Received: " + line);
            }
        }
        protocol.close();
    }

    static byte[] loadPsk() throws Exception {
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"),
                "changeit".toCharArray());

        return keyStore.getKey("aes-key", "changeit".toCharArray()).getEncoded();
    }
}
