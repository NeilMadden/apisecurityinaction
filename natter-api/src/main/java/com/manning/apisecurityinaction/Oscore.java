package com.manning.apisecurityinaction;

import COSE.*;
import com.upokecenter.cbor.CBORObject;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.*;
import java.security.*;

public class Oscore {

    private static Key deriveKey(Key hkdfKey, byte[] id,
        byte[] idContext, AlgorithmID coseAlgorithm)
            throws GeneralSecurityException {

        int keySizeBytes = coseAlgorithm.getKeySize() / 8;
        CBORObject context = CBORObject.NewArray();
        context.Add(id);
        context.Add(idContext);
        context.Add(coseAlgorithm.AsCBOR());
        context.Add(CBORObject.FromObject("Key"));
        context.Add(keySizeBytes);

        return HKDF.expand(hkdfKey, context.EncodeToBytes(),
                keySizeBytes, "AES");
    }

    private static byte[] deriveCommonIV(Key hkdfKey,
        byte[] idContext, AlgorithmID coseAlgorithm, int ivLength)
            throws GeneralSecurityException {
        CBORObject context = CBORObject.NewArray();
        context.Add(new byte[0]);
        context.Add(idContext);
        context.Add(coseAlgorithm.AsCBOR());
        context.Add(CBORObject.FromObject("IV"));
        context.Add(ivLength);

        return HKDF.expand(hkdfKey, context.EncodeToBytes(),
                ivLength, "dummy").getEncoded();
    }

    private static byte[] nonce(int ivLength, long sequenceNumber,
                                byte[] id, byte[] commonIv) {
        if (sequenceNumber > (1L << 40))
            throw new IllegalArgumentException("Sequence number too large");
        int idLen = ivLength - 6;
        if (id.length > idLen)
            throw new IllegalArgumentException("ID is too large");

        var buffer = ByteBuffer.allocate(ivLength).order(ByteOrder.BIG_ENDIAN);
        buffer.put((byte) id.length);
        buffer.put(new byte[idLen - id.length]);
        buffer.put(id);
        buffer.put((byte) ((sequenceNumber >>> 32) & 0xFF));
        buffer.putInt((int) sequenceNumber);
        return xor(buffer.array(), commonIv);
    }

    private static byte[] xor(byte[] xs, byte[] ys) {
        for (int i = 0; i < xs.length; ++i)
            xs[i] ^= ys[i];
        return xs;
    }

    public static void main(String... args) throws Exception {
        var algorithm = AlgorithmID.AES_CCM_16_64_128;
        var masterKey = new byte[] {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
        };
        var masterSalt = new byte[] {
                (byte) 0x9e, 0x7c, (byte) 0xa9, 0x22, 0x23, 0x78,
                0x63, 0x40
        };
        var hkdfKey = HKDF.extract(masterSalt, masterKey);
        var senderId = new byte[0];
        var recipientId = new byte[] { 0x01 };

        var senderKey = deriveKey(hkdfKey, senderId, null, algorithm);
        var recipientKey = deriveKey(hkdfKey, recipientId, null, algorithm);
        var commonIv = deriveCommonIV(hkdfKey, null, algorithm, 13);

        System.out.println(Hex.encodeHex(senderKey.getEncoded()));
        System.out.println(Hex.encodeHex(recipientKey.getEncoded()));
        System.out.println(Hex.encodeHex(commonIv));

        long sequenceNumber = 20L;
        byte[] nonce = nonce(13, sequenceNumber, senderId, commonIv);
        byte[] partialIv = new byte[] { (byte) sequenceNumber };

        var message = new Encrypt0Message();
        message.addAttribute(HeaderKeys.Algorithm,
                algorithm.AsCBOR(), Attribute.DO_NOT_SEND);
        message.addAttribute(HeaderKeys.IV,
                nonce, Attribute.DO_NOT_SEND);
        message.addAttribute(HeaderKeys.PARTIAL_IV,
                partialIv, Attribute.UNPROTECTED);
        message.addAttribute(HeaderKeys.KID,
                senderId, Attribute.UNPROTECTED);
        message.SetContent(
                new byte[] { 0x01, (byte) 0xb3, 0x74, 0x76, 0x31});

        var associatedData = CBORObject.NewArray();
        associatedData.Add(1);
        associatedData.Add(algorithm.AsCBOR());
        associatedData.Add(senderId);
        associatedData.Add(partialIv);
        associatedData.Add(new byte[0]);
        message.setExternal(associatedData.EncodeToBytes());

        Security.addProvider(new BouncyCastleProvider());
        message.encrypt(senderKey.getEncoded());
        System.out.println(Hex.encodeHex(message.getEncryptedContent()));
    }
}
