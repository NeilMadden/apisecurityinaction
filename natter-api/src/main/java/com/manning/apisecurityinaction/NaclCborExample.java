package com.manning.apisecurityinaction;

import com.upokecenter.cbor.CBORObject;
import software.pando.crypto.nacl.*;

public class NaclCborExample {
    public static void main(String... args) {
        var senderKeys = CryptoBox.keyPair();
        var recipientKeys = CryptoBox.keyPair();
        var cborMap = CBORObject.NewMap()
                .Add("foo", "bar")
                .Add("data", 12345);
        var sent = CryptoBox.encrypt(senderKeys.getPrivate(),
                recipientKeys.getPublic(), cborMap.EncodeToBytes());

        var recvd = CryptoBox.fromString(sent.toString());
        var cbor = recvd.decrypt(recipientKeys.getPrivate(),
                senderKeys.getPublic());
        System.out.println(CBORObject.DecodeFromBytes(cbor));
    }
}
