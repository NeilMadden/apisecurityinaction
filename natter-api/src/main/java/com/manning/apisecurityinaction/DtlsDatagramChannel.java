package com.manning.apisecurityinaction;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.DatagramChannel;

import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.*;

import org.slf4j.*;

/**
 * A rudimentary wrapper around the {@link SSLEngine} low-level DTLS
 * protocol state machine.
 * <p>
 * <strong>Note:</strong> this class doesn't attempt to handle timeouts,
 * lost packets, retransmissions, buffer overflows, and many other details
 * of a robust UDP-based protocol implementation. It implements enough
 * to provide a guidance to DTLS usage in Java. When used as a server,
 * this class only supports a single client at a time and will discard
 * packets received from other concurrent clients.
 */
public class DtlsDatagramChannel implements Closeable {
    private static final Logger logger = LoggerFactory.getLogger(DtlsDatagramChannel.class);

    private final DatagramChannel channel;
    private final SSLContext sslContext;
    private final SSLParameters sslParameters;

    private ByteBuffer netRecvBuffer;
    private ByteBuffer netSendBuffer;
    private ByteBuffer appBuffer;

    private SSLEngine sslEngine;

    public DtlsDatagramChannel(SSLContext sslContext, SSLParameters sslParameters) throws IOException {
        this.channel = DatagramChannel.open();
        this.sslContext = sslContext;
        this.sslParameters = sslParameters;

        this.netRecvBuffer = ByteBuffer.allocateDirect(2048);
    }

    public DtlsDatagramChannel(SSLContext sslContext) throws IOException {
        this(sslContext, defaultSslParameters());
    }

    public static SSLParameters defaultSslParameters() {
        var params = new SSLParameters();
        params.setProtocols(new String[] { "DTLSv1.2" });
        params.setMaximumPacketSize(1500);
        params.setEnableRetransmissions(true);
        params.setEndpointIdentificationAlgorithm("HTTPS");
        return params;
    }


    public DtlsDatagramChannel bind(int port) throws IOException {
        channel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        return this;
    }

    public DtlsDatagramChannel connect(String host, int port) throws IOException {
        channel.connect(new InetSocketAddress(host, port));
        return this;
    }

    public SSLSession getSession() {
        return sslEngine.getSession();
    }

    public void send(byte[] data) throws IOException {
        if (!channel.isConnected()) {
            throw new IllegalStateException("Channel must be connected");
        }

        if (sslEngine == null) {
            var socketAddr = ((InetSocketAddress) channel.getRemoteAddress());
            sslEngine = sslContext.createSSLEngine(socketAddr.getHostName(), socketAddr.getPort());
            sslEngine.setUseClientMode(true);
            sslEngine.setSSLParameters(sslParameters);

            handshake(sslEngine);
        }

        if (sslEngine.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING) {
            throw new IllegalStateException("DTLS handshake failed");
        }

        appBuffer.put(data);
        appBuffer.flip();
        var result = sslEngine.wrap(appBuffer, netSendBuffer);
        appBuffer.compact();

        if (result.getStatus() != Status.OK) {
            throw new IllegalStateException("Wrap failed: " + result);
        }

        netSendBuffer.flip();
        channel.write(netSendBuffer);
        netSendBuffer.compact();
    }

    public InetSocketAddress receive(ByteBuffer buffer) throws IOException {
        var address = (InetSocketAddress) channel.receive(netRecvBuffer);
        if (!channel.isConnected()) {
            channel.connect(address);
        }
        if (sslEngine == null) {
            sslEngine = sslContext.createSSLEngine(address.getHostName(), address.getPort());
            sslEngine.setUseClientMode(false);
            sslEngine.setSSLParameters(sslParameters);

            handshake(sslEngine);
            channel.receive(netRecvBuffer);
        }

        netRecvBuffer.flip();
        var result = sslEngine.unwrap(netRecvBuffer, buffer);
        netRecvBuffer.compact();

        if (result.getStatus() == Status.BUFFER_UNDERFLOW) {
            throw new BufferUnderflowException();
        }
        if (result.getStatus() == Status.BUFFER_OVERFLOW) {
            throw new BufferOverflowException();
        }
        if (result.getStatus() == Status.CLOSED) {
            logger.info("Client disconnected");
            sslEngine.closeInbound();
            processEngineLoop(sslEngine);
            sslEngine.closeOutbound();
            channel.disconnect();
            sslEngine = null;
        }

        return address;
    }

    @Override
    public void close() throws IOException {
        sslEngine.closeOutbound();
        // We should be able to call processEngineLoop here, but in OpenJDK 13
        // it erroneously returns HANDSHAKE_DONE when we are still waiting for
        // the other side's close_notify alert.

        // Send close_notify alert
        appBuffer.flip();
        sslEngine.wrap(appBuffer, netSendBuffer);
        appBuffer.compact();
        netSendBuffer.flip();
        if (netSendBuffer.hasRemaining()) {
            channel.write(netSendBuffer);
            netSendBuffer.compact();
        }

        // Wait for close_notify response
        while (!sslEngine.isInboundDone()) {
            channel.receive(netRecvBuffer);
            netRecvBuffer.flip();
            sslEngine.unwrap(netRecvBuffer, appBuffer);
            netRecvBuffer.compact();
        }
        sslEngine.closeInbound();
        channel.close();
    }

    private void handshake(SSLEngine engine) throws IOException {
        if (!channel.isConnected()) {
            throw new IllegalStateException("Channel must be connected");
        }
        logger.info("Beginning DTLS handshake");
        engine.beginHandshake();

        appBuffer = ByteBuffer.allocateDirect(engine.getSession().getApplicationBufferSize());
        netSendBuffer = ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());

        processEngineLoop(engine);
    }

    private void processEngineLoop(SSLEngine engine) throws IOException {
        var status = engine.getHandshakeStatus();
        while (status != HandshakeStatus.FINISHED && status != HandshakeStatus.NOT_HANDSHAKING) {
            SSLEngineResult result;
            logger.debug("Handshake status: " + status);
            switch (status) {
                case NEED_UNWRAP:
                    if (netRecvBuffer.position() == 0) {
                        channel.receive(netRecvBuffer);
                    }
                case NEED_UNWRAP_AGAIN:
                    netRecvBuffer.flip();
                    result = engine.unwrap(netRecvBuffer, appBuffer);
                    netRecvBuffer.compact();
                    logger.debug("Unwrap result: {}", result);

                    while (result.getStatus() == Status.BUFFER_UNDERFLOW) {
                        netRecvBuffer = ensureCapacity(netRecvBuffer,
                                sslEngine.getSession().getPacketBufferSize());
                        channel.receive(netRecvBuffer);
                        netRecvBuffer.flip();
                        result = engine.unwrap(netRecvBuffer, appBuffer);
                        netRecvBuffer.compact();
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
                    appBuffer.flip();
                    result = engine.wrap(appBuffer, netSendBuffer);
                    appBuffer.compact();
                    logger.debug("Wrap result: " + result);

                    netSendBuffer.flip();
                    if (netSendBuffer.hasRemaining()) {
                        channel.write(netSendBuffer);
                        netSendBuffer.compact();
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

    private ByteBuffer ensureCapacity(ByteBuffer buffer, int requiredSize) {
        var remaining = buffer.remaining();
        if (remaining < requiredSize) {
            var newBuffer = ByteBuffer.allocate(buffer.position() + requiredSize);
            newBuffer.put(buffer.flip());
            return newBuffer;
        }
        return buffer;
    }
}
