package com.manning.apisecurityinaction;

import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.*;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;

import org.slf4j.*;

import static java.util.Objects.requireNonNull;

/**
 * A wrapper over the UDP {@link DatagramSocket} that provides support
 * for DTLS transport security. A DTLS handshake will be performed
 */
public class DtlsDatagramSocket extends DatagramSocket {
    private static final Logger logger = LoggerFactory.getLogger(DtlsDatagramSocket.class);
    private static final int HANDSHAKE_PACKET_SIZE = 1024;

    private final SSLContext sslContext;
    private final SSLParameters sslParameters;

    private SSLEngine sslEngine;

    /**
     * Initializes the datagram socket with the given DTLS context
     * and parameters. The socket will be bound to an arbitrary
     * free local port chosen by the operating system.
     *
     * @param sslContext the ssl context.
     * @param sslParameters the ssl parameters.
     * @exception  SocketException  if the socket could not be opened,
     *               or the socket could not bind to any local port.
     * @exception  SecurityException  if a security manager exists and its
     *             {@code checkListen} method doesn't allow the operation.
     */
    public DtlsDatagramSocket(SSLContext sslContext,
                              SSLParameters sslParameters)
            throws SocketException {
        this(sslContext, sslParameters, 0);
    }

    /**
     * Initializes the datagram socket with the given DTLS context
     * and parameters. The socket will be bound to the given local
     * port.
     *
     * @param sslContext the ssl context.
     * @param sslParameters the ssl parameters.
     * @param port the local port to bind to.
     * @exception  SocketException  if the socket could not be opened,
     *               or the socket could not bind to the given port.
     * @exception  SecurityException  if a security manager exists and its
     *             {@code checkListen} method doesn't allow the operation.
     */
    public DtlsDatagramSocket(SSLContext sslContext,
                              SSLParameters sslParameters, int port)
            throws SocketException {
        super(port);
        if (!"DTLS".equalsIgnoreCase(sslContext.getProtocol())) {
            throw new IllegalArgumentException("SSLContext not for DTLS");
        }
        this.sslContext = requireNonNull(sslContext);
        this.sslParameters = requireNonNull(sslParameters);
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        // Force the use of connected ports to avoid juggling handshakes
        // for different destinations.
        if (!isConnected()) {
            throw new IllegalStateException("Socket must be connected");
        }

        if (sslEngine == null) {
            sslEngine = sslContext.createSSLEngine(
                    getInetAddress().getHostName(), getPort());
            sslEngine.setSSLParameters(sslParameters);
            sslEngine.setUseClientMode(true);

            handshake(sslEngine, packet);
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
        logger.debug("Sending packet, size={}", networkBuffer.remaining());
        DtlsPacketDebug.debug(networkBuffer);
        var buffer = new byte[networkBuffer.remaining()];
        networkBuffer.get(buffer);
        packet = new DatagramPacket(buffer, buffer.length,
                packet.getSocketAddress());
        super.send(packet);
    }

    /**
     * Returns the SSL session object associated with this socket.
     *
     * @return the ssl session.
     */
    public SSLSession getSession() {
        return sslEngine == null ? null : sslEngine.getSession();
    }

    @Override
    public synchronized void receive(DatagramPacket packet) throws IOException {
        if (sslEngine == null) {
            sslEngine = sslContext.createSSLEngine();
            sslEngine.setSSLParameters(sslParameters);
            sslEngine.setUseClientMode(false);

            handshake(sslEngine, packet);
        }
        super.receive(packet);
        logger.debug("Received packet, length={}", packet.getLength());

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

    private void handshake(SSLEngine engine, DatagramPacket originalPacket) throws IOException {
        logger.debug("Beginning DTLS handshake");
        engine.beginHandshake();

        var netData = ByteBuffer.allocate(HANDSHAKE_PACKET_SIZE);
        var appData = ByteBuffer.allocate(HANDSHAKE_PACKET_SIZE);

        var packet = new DatagramPacket(new byte[HANDSHAKE_PACKET_SIZE],
                HANDSHAKE_PACKET_SIZE);
        if (originalPacket.getPort() != -1) {
            packet.setSocketAddress(originalPacket.getSocketAddress());
        }

        var status = engine.getHandshakeStatus();
        SSLEngineResult result;
        while (status != HandshakeStatus.FINISHED) {
            logger.debug("Handshake status: " + status);
            switch (status) {
                case NEED_UNWRAP:
                    super.receive(packet);
                    logger.debug("Packed received, size={}", packet.getLength());
                    netData.put(packet.getData(), packet.getOffset(), packet.getLength());
                    DtlsPacketDebug.debug(netData);
                    netData.flip();
                    result = engine.unwrap(netData, appData);
                    netData.compact();
                    logger.debug("Unwrap result: {}", result);

                    if (result.getStatus() != Status.OK) {
                        throw new IllegalStateException("Unwrap failed: " + result);
                    }

                    status = result.getHandshakeStatus();
                    break;
                case NEED_UNWRAP_AGAIN:
                    netData.flip();
                    result = engine.unwrap(netData, appData);
                    netData.compact();
                    logger.debug("Unwrap result: {}", result);

                    if (result.getStatus() != Status.OK) {
                        throw new IllegalStateException("Unwrap failed: " + result);
                    }

                    status = result.getHandshakeStatus();
                    break;
                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        logger.debug("Running task: {}", task);
                        task.run();
                    }
                    status = engine.getHandshakeStatus();
                    logger.debug("Tasks executed");
                    break;
                case NEED_WRAP:
                    result = engine.wrap(appData, netData);
                    logger.debug("Wrap result: " + result);

                    if (result.getStatus() != Status.OK) {
                        throw new IllegalStateException("Wrap failed: " + result);
                    }

                    netData.flip();
                    DtlsPacketDebug.debug(netData);

                    if (netData.hasRemaining()) {
                        var buffer = new byte[netData.remaining()];
                        netData.get(buffer);
                        packet.setData(buffer);
                        logger.debug("Sending packet to: {}, size={}",
                                packet.getSocketAddress(),
                                packet.getLength());
                        super.send(packet);
                    }
                    status = result.getHandshakeStatus();
                    break;
                default:
                    throw new IllegalStateException(
                            "Unexpected handshake state: " + status);
            }
        }
        logger.debug("Handshake finished!");
    }
}
