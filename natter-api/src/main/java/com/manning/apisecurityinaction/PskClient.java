package com.manning.apisecurityinaction;

import java.io.PrintStream;
import java.net.Socket;
import java.nio.file.*;
import java.security.SecureRandom;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import software.pando.crypto.nacl.Crypto;

public class PskClient {

    public static void main(String[] args) throws Exception {
        var psk = PskServer.loadPsk();
        var pskId = Crypto.hash(psk);

        var crypto = new BcTlsCrypto(new SecureRandom());
        var client = new PSKTlsClient(crypto, pskId, psk) {
            @Override
            protected int[] getSupportedCipherSuites() {
                return new int[] {
                        CipherSuite.TLS_PSK_WITH_AES_128_CCM
                };
            }
        };

        var socket = new Socket("localhost", 54321);

        var protocol = new TlsClientProtocol(socket.getInputStream(),
                socket.getOutputStream());
        protocol.connect(client);

        try (var out = new PrintStream(protocol.getOutputStream());
             var in = Files.newBufferedReader(Paths.get("test.txt"))) {

            in.lines().forEach(out::println);
        }
    }
}
