package com.manning.apisecurityinaction;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;

public class UdpClient {
    public static void main(String... args) throws Exception {
        var serverAddr = new InetSocketAddress("localhost", 54321);

        try (var socket = new DatagramSocket();
             var in = Files.newBufferedReader(Paths.get("test.txt"))) {
            var buffer = new byte[UdpServer.PACKET_SIZE];
            var packet = new DatagramPacket(buffer, buffer.length);
            packet.setSocketAddress(serverAddr);

            String line;
            while ((line = in.readLine()) != null) {
                System.out.println("Sending packet to server");
                packet.setData(line.getBytes(UTF_8));
                socket.send(packet);
            }

            System.out.println("All packets sent");
        }
    }
}
