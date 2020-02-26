package com.manning.apisecurityinaction;

import static com.manning.apisecurityinaction.UdpServer.PACKET_SIZE;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;

import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.*;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.*;

public class DTLSDatagramSocket extends DatagramSocket {
    private static final Logger logger = LoggerFactory.getLogger(DTLSDatagramSocket.class);

    private final SSLContext sslContext;

    private SSLEngine sslEngine;

    public DTLSDatagramSocket(SSLContext sslContext) throws SocketException {
        this(sslContext, 0);
    }

    public DTLSDatagramSocket(SSLContext sslContext, int port) throws SocketException {
        super(port);
        if (!"DTLS".equalsIgnoreCase(sslContext.getProtocol())) {
            throw new IllegalArgumentException("SSLContext not for DTLS");
        }
        this.sslContext = sslContext;
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {

        if (sslEngine == null || !sslEngine.getUseClientMode() ||
            !sslEngine.getPeerHost().equals(packet.getAddress().getHostName()) ||
            sslEngine.getPeerPort() != packet.getPort()) {

            sslEngine = sslContext.createSSLEngine(
                    packet.getAddress().getHostName(),
                    packet.getPort());
            var params = sslEngine.getSSLParameters();
            params.setMaximumPacketSize(packet.getData().length);
            sslEngine.setSSLParameters(params);
            sslEngine.setUseClientMode(true);

            handshake(sslEngine);
        }

        if (sslEngine.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING) {
            throw new IllegalStateException("DTLS handshake failed");
        }

        var sendBuffer = ByteBuffer.wrap(packet.getData(),
                packet.getOffset(), packet.getLength());
        var networkBuffer = ByteBuffer.allocate(16384);
        var result = sslEngine.wrap(sendBuffer, networkBuffer);
        if (result.getStatus() != Status.OK) {
            throw new IOException("Error creating DTLS packet: " +
                    result);
        }

        networkBuffer.flip();
        var buffer = new byte[networkBuffer.remaining()];
        networkBuffer.get(buffer);
        packet = new DatagramPacket(buffer, buffer.length,
                packet.getSocketAddress());
        logger.info("Sending packet: " + Hex.encodeHexString(buffer));
        super.send(packet);
    }

    @Override
    public synchronized void receive(DatagramPacket packet) throws IOException {
        if (sslEngine == null || sslEngine.getUseClientMode()) {

            sslEngine = sslContext.createSSLEngine();
            var params = sslEngine.getSSLParameters();
            params.setMaximumPacketSize(packet.getData().length);
            sslEngine.setSSLParameters(params);
            sslEngine.setUseClientMode(false);

            handshake(sslEngine);
        }
        super.receive(packet);
        logger.info("Received packet length={}", packet.getLength());
        logger.info("Packet size: {}", packet.getData().length);

        var network = ByteBuffer.wrap(packet.getData(),
                packet.getOffset(), packet.getLength());
        var application = ByteBuffer.allocate(packet.getData().length);
        var result = sslEngine.unwrap(network, application);
        if (result.getStatus() != Status.OK) {
            throw new IOException("DTLS error: " + result);
        }

        var len = application.flip().remaining();
        application.get(packet.getData(), 0,
                Math.min(len, packet.getData().length));
        packet.setLength(len);
    }

    private void handshake(SSLEngine engine) throws IOException {
        logger.info("Beginning DTLS handshake");
        engine.beginHandshake();

        var packet = new DatagramPacket(new byte[PACKET_SIZE], PACKET_SIZE);
        packet.setSocketAddress(new InetSocketAddress("localhost", 54321));

        ByteBuffer networkData;
        ByteBuffer applicationData = ByteBuffer.allocate(PACKET_SIZE);
        var status = engine.getHandshakeStatus();
        SSLEngineResult result;
        while (status != HandshakeStatus.FINISHED) {
            logger.info("Status: " + status);
            switch (status) {
                case NEED_UNWRAP:
                    packet.setData(new byte[PACKET_SIZE]);
                    super.receive(packet);
                    logger.info("Packed received, size={}", packet.getLength());
                    networkData = ByteBuffer.wrap(packet.getData(), 0,
                            packet.getLength());
                    applicationData = ByteBuffer.allocate(PACKET_SIZE);
                    result = engine.unwrap(networkData, applicationData);
                    logger.info("Unwrap result: {}", result);

                    status = result.getHandshakeStatus();
                    break;
                case NEED_UNWRAP_AGAIN:
                    networkData = ByteBuffer.allocate(0);
                    applicationData = ByteBuffer.allocate(PACKET_SIZE);
                    result = engine.unwrap(networkData, applicationData);
                    logger.info("Unwrap result: {}", result);
                    status = result.getHandshakeStatus();
                    break;
                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        logger.info("Running task: {}", task);
                        task.run();
                    }
                    status = engine.getHandshakeStatus();
                    logger.info("Tasks executed");
                    break;
                case NEED_WRAP:
                    applicationData = ByteBuffer.allocate(0);
                    networkData = ByteBuffer.allocate(32768);
                    result = engine.wrap(applicationData, networkData);
                    logger.info("Wrap result: " + result);
                    status = result.getHandshakeStatus();
                    networkData.flip();

                    if (networkData.hasRemaining()) {
                        var buffer = new byte[networkData.remaining()];
                        networkData.get(buffer);
                        packet.setData(buffer);
                        logger.info("Sending packet to: {}, size={}",
                                packet.getSocketAddress(),
                                packet.getLength());
                        super.send(packet);
                    }
                    break;
                default:
                    throw new IllegalStateException(
                            "Unexpected handshake state: " + status);
            }
        }
        logger.info("Handshake finished!");
    }

}
