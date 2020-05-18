package com.manning.apisecurityinaction;

import com.upokecenter.cbor.CBORObject;
import software.pando.crypto.nacl.CryptoBox;

import java.net.URI;
import java.net.http.*;
import java.security.KeyPair;
import java.util.concurrent.atomic.AtomicInteger;

import static java.lang.Integer.parseInt;
import static java.net.http.HttpResponse.BodyHandlers.ofString;
import static spark.Spark.*;

public class ReplayProtectionExample implements Runnable {
    private static final KeyPair clientKeys = CryptoBox.keyPair();
    private static final KeyPair serverKeys = CryptoBox.keyPair();

    public static void main(String... args) throws Exception {
        new Thread(new ReplayProtectionExample()).start();

        var revisionEtag = "42";
        var headers = CBORObject.NewMap()
                .Add("If-Matches", revisionEtag);
        var body = CBORObject.NewMap()
                .Add("foo", "bar")
                .Add("data", 12345);
        var request = CBORObject.NewMap()
                .Add("method", "PUT")
                .Add("headers", headers)
                .Add("body", body);
        var sent = CryptoBox.encrypt(clientKeys.getPrivate(),
                serverKeys.getPublic(), request.EncodeToBytes());

        var httpRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:4567/test"))
                .header("If-Matches", revisionEtag)
                .PUT(HttpRequest.BodyPublishers.ofString(sent.toString()))
                .build();
        var httpResponse = HttpClient.newHttpClient().send(httpRequest, ofString());
        System.out.println("Received response: " + httpResponse.statusCode());
        System.out.println("ETag: " + httpResponse.headers().allValues("ETag"));
    }

    @Override
    public void run() {

        before((request, response) -> {
            var encryptedRequest = CryptoBox.fromString(request.body());
            var decrypted = encryptedRequest.decrypt(
                    serverKeys.getPrivate(), clientKeys.getPublic());
            var cbor = CBORObject.DecodeFromBytes(decrypted);

            if (!cbor.get("method").AsString()
                    .equals(request.requestMethod())) {
                halt(403);
            }

            var expectedHeaders = cbor.get("headers");
            for (var headerName : expectedHeaders.getKeys()) {
                if (!expectedHeaders.get(headerName).AsString()
                        .equals(request.headers(headerName.AsString()))) {
                    halt(403);
                }
            }

            request.attribute("decryptedRequest", cbor.get("body"));
        });

        // Simulate updating an ETag using an AtomicInteger. In a
        // real example the ETag would be stored alongside the data
        // and updated in a transaction.
        var etag = new AtomicInteger(42);
        put("/test", (request, response) -> {
            var expectedEtag = parseInt(request.headers("If-Matches"));

            if (!etag.compareAndSet(expectedEtag, expectedEtag + 1)) {
                response.status(412);
                return null;
            }

            System.out.println("Updating resource with new content: " +
                    request.attribute("decryptedRequest"));

            response.status(200);
            response.header("ETag", String.valueOf(expectedEtag + 1));
            response.type("text/plain");
            return "OK";
        });
    }
}
