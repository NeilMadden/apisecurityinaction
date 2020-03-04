package com.manning.apisecurityinaction;

import java.nio.*;

import org.slf4j.*;

/**
 * Utility methods for debugging (D)TLS record layer and handshake
 * messages.
 */
class DtlsPacketDebug {
    private static final Logger logger = LoggerFactory.getLogger(DtlsPacketDebug.class);

    enum TlsVersion {
        SSL_2_0(2, 0),
        SSL_3_0(3, 0),
        TLS_1_0(3, 1),
        TLS_1_1(3, 2),
        TLS_1_2(3, 3), // Or later, as TLS 1.3 reuses the same version
        DTLS_1_0(254, 255),
        DTLS_1_2(254, 253);
        final byte major;
        final byte minor;

        TlsVersion(int major, int minor) {
            this.major = (byte) major;
            this.minor = (byte) minor;
        }

        static TlsVersion get(byte major, byte minor) {
            for (var candidate : values()) {
                if (candidate.major == major && candidate.minor == minor)
                    return candidate;
            }
            return null;
        }
    }

    enum ContentType {
        CHANGE_CIPHER_SPEC(20),
        ALERT(21),
        HANDSHAKE(22),
        APPLICATION_DATA(23);

        final byte value;

        ContentType(int value) {
            this.value = (byte) value;
        }

        static ContentType get(byte value) {
            for (var type : values()) {
                if (type.value == value)
                    return type;
            }
            return null;
        }
    }

    // Handshake message types
    enum HandshakeMessageType {
        HELLO_REQUEST(0),
        CLIENT_HELLO(1),
        SERVER_HELLO(2),
        HELLO_VERIFY_REQUEST(3), // DTLS-specific
        CERTIFICATE(11),
        SERVER_KEY_EXCHANGE(12),
        CERTIFICATE_REQUEST(13),
        SERVER_HELLO_DONE(14),
        CERTIFICATE_VERIFY(15),
        CLIENT_KEY_EXCHANGE(16),
        FINISHED(20)
        ;

        final byte type;

        HandshakeMessageType(int type) {
            this.type = (byte) type;
        }

        static HandshakeMessageType get(byte value) {
            for (var candidate : values()) {
                if (candidate.type == value) {
                    return candidate;
                }
            }
            return null;
        }
    }


    static void debug(ByteBuffer data) {
        var packet = data.duplicate().order(ByteOrder.BIG_ENDIAN);

        var info = new StringBuilder();

        var packetType = ContentType.get(packet.get());
        info.append(packetType).append(" ");

        var protoMajor = packet.get();
        var protoMinor = packet.get();
        var version = TlsVersion.get(protoMajor, protoMinor);
        info.append(version).append(" ");

        var epoch = packet.getShort() & 0xFFFF;
        var sequence = ((packet.getInt() & 0xFFFFFFFFL) << 16)
                | (packet.getShort() & 0xFFFFL);
        var length = packet.getShort() & 0xFFFF;

        info.append("epoch=").append(epoch).append(", seq=")
                .append(sequence).append(", len=").append(length)
                .append(" ");

        if (packetType == ContentType.HANDSHAKE) {
            var messageType = HandshakeMessageType.get(packet.get());
            info.append(messageType);

            var messageLen = ((packet.getShort() & 0xFFFF) << 8)
                    | (packet.get() & 0xFF);

            info.append(" (len=").append(messageLen).append(") ");
        }

        logger.debug(info.toString());
    }
}
