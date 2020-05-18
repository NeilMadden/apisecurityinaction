package com.manning.apisecurityinaction;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import software.pando.crypto.nacl.SecretBox;

import java.io.FileInputStream;
import java.net.*;
import java.security.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class PskServer {
    public static void main(String[] args) throws Exception {
        var psk = loadPsk(args[0].toCharArray());
        var encryptionKey = SecretBox.key();
        var deviceDb = Device.createDatabase(
                SecretBox.encrypt(encryptionKey, psk));
        var crypto = new BcTlsCrypto(new SecureRandom());
        var server = new PSKTlsServer(crypto,
                new DeviceIdentityManager(deviceDb, encryptionKey)) {
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return ProtocolVersion.DTLSv12.only();
            }
            @Override
            protected int[] getSupportedCipherSuites() {
                return new int[] {
                        CipherSuite.TLS_PSK_WITH_AES_128_CCM,
                        CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
                        CipherSuite.TLS_PSK_WITH_AES_256_CCM,
                        CipherSuite.TLS_PSK_WITH_AES_256_CCM_8,
                        CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
                };
            }

            String getPeerDeviceIdentity() {
                return new String(context.getSecurityParametersConnection()
                        .getPSKIdentity(), UTF_8);
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
            if (len == -1) break;
            System.out.println("Receiving data from device: " +
                    server.getPeerDeviceIdentity());
            var data = new String(buffer, 0, len, UTF_8);
            System.out.println("Received: " + data);
        }
    }

    static byte[] loadPsk(char[] password) throws Exception {
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"), password);
        return keyStore.getKey("aes-key", password).getEncoded();
    }
}
