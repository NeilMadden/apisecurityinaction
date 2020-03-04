package com.manning.apisecurityinaction;

import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.*;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;

import org.slf4j.*;

public class DtlsDatagramChannel implements Closeable {
    private static final Logger logger = LoggerFactory.getLogger(DtlsDatagramChannel.class);

    private final DatagramChannel channel;
    private final SSLContext sslContext;
    private final SSLParameters sslParameters;

    private final ByteBuffer netRecvBuffer;
    private final ByteBuffer netSendBuffer;
    private final ByteBuffer appBuffer;

    private SSLEngine sslEngine;

    public DtlsDatagramChannel(SSLContext sslContext, SSLParameters sslParameters) throws IOException {
        this.channel = DatagramChannel.open();
        this.sslContext = sslContext;
        this.sslParameters = sslParameters;

        this.netRecvBuffer = ByteBuffer.allocate(2048);
        this.netSendBuffer = ByteBuffer.allocate(65535);
        this.appBuffer = ByteBuffer.allocate(2048);
    }

    public void bind(int port) throws IOException {
        channel.bind(new InetSocketAddress(InetAddress.getLocalHost(), port));
    }

    public void connect(String host, int port) throws IOException {
        channel.connect(new InetSocketAddress(host, port));
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
        }

        channel.receive(netRecvBuffer);
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
            throw new ClosedChannelException();
        }

        return address;
    }

    @Override
    public void close() throws IOException {
        sslEngine.closeOutbound();
        sslEngine.closeInbound();
    }

    private void handshake(SSLEngine engine) throws IOException {
        if (!channel.isConnected()) {
            throw new IllegalStateException("Channel must be connected");
        }
        logger.debug("Beginning DTLS handshake");
        engine.beginHandshake();

        var status = engine.getHandshakeStatus();
        SSLEngineResult result;
        while (status != HandshakeStatus.FINISHED) {
            logger.debug("Handshake status: " + status);
            switch (status) {
                case NEED_UNWRAP:
                    netRecvBuffer.flip();
                    result = engine.unwrap(netRecvBuffer, appBuffer);
                    netRecvBuffer.compact();
                    logger.debug("Unwrap result: {}", result);

                    if (result.getStatus() == Status.BUFFER_UNDERFLOW) {
                        channel.receive(netRecvBuffer);
                        netRecvBuffer.flip();
                        DtlsPacketDebug.debug(netRecvBuffer);
                        result = engine.unwrap(netRecvBuffer, appBuffer);
                        netRecvBuffer.compact();
                    }

                    if (result.getStatus() != Status.OK) {
                        throw new IllegalStateException("Unwrap failed: " + result);
                    }

                    status = result.getHandshakeStatus();
                    break;
                case NEED_UNWRAP_AGAIN:
                    netRecvBuffer.flip();
                    result = engine.unwrap(netRecvBuffer, appBuffer);
                    netRecvBuffer.compact();
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
                    result = engine.wrap(appBuffer, netSendBuffer);
                    appBuffer.compact();
                    logger.debug("Wrap result: " + result);

                    if (result.getStatus() != Status.OK) {
                        throw new IllegalStateException("Wrap failed: " + result);
                    }

                    netSendBuffer.flip();
                    DtlsPacketDebug.debug(netSendBuffer);
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
}
