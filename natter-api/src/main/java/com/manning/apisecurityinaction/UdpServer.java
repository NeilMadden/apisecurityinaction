package com.manning.apisecurityinaction;

import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class UdpServer {
    static final int PACKET_SIZE = 1024;

    public static void main(String... args) throws Exception {
        try (var socket = new DatagramSocket(54321)) {
            System.out.printf("Listening on port %d%n",
                    socket.getLocalPort());

            var buffer = new byte[PACKET_SIZE];
            var packet = new DatagramPacket(buffer, PACKET_SIZE);

            while (true) {
                socket.receive(packet);
                System.out.printf("Received packet from %s - len: %d%n",
                        packet.getSocketAddress(), packet.getLength());

                var message = new String(buffer, 0, packet.getLength());
                System.out.println("Message: " + message);
            }
        }
    }
}
