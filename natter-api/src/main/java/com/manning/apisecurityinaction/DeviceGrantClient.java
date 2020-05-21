package com.manning.apisecurityinaction;

import org.json.JSONObject;
import java.net.*;
import java.net.http.*;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.concurrent.TimeUnit;
import static java.nio.charset.StandardCharsets.UTF_8;

public class DeviceGrantClient {
    private static final HttpClient httpClient = HttpClient.newHttpClient();

    public static void main(String... args) throws Exception {
        var clientId = "deviceGrantTest";
        var scope = "a b c";

        // Make initial request to device authorization endpoint
        var json = beginDeviceAuthorization(clientId, scope);
        var deviceCode = json.getString("device_code");
        var interval = json.optInt("interval", 5);
        System.out.println("Please open " + json.getString("verification_uri"));
        System.out.println("And enter code:\n\t" + json.getString("user_code"));
        System.out.println("I'm waiting!");

        while (true) {
            Thread.sleep(TimeUnit.SECONDS.toMillis(interval));
            json = pollAccessTokenEndpoint(clientId, deviceCode);
            var error = json.optString("error", null);
            if (error != null) {
                switch (error) {
                    case "slow_down":
                        System.out.println("Slowing down");
                        interval += 5;
                        break;
                    case "authorization_pending":
                        System.out.println("Still waiting!");
                        break;
                    default:
                        System.err.println("Authorization failed: " + error);
                        System.exit(1);
                        break;
                }
            } else {
                System.out.println("Access token: " + json.getString("access_token"));
                break;
            }
        }
    }

    private static JSONObject beginDeviceAuthorization(
            String clientId, String scope) throws Exception {
        var form = "client_id=" + URLEncoder.encode(clientId, UTF_8) +
                "&scope=" + URLEncoder.encode(scope, UTF_8) +
                "&response_type=device_code";
        var request = HttpRequest.newBuilder()
                .header("Content-Type",
                        "application/x-www-form-urlencoded")
                .uri(URI.create(
                        "https://as.example.com:8443/openam/oauth2/device/code"))
                .POST(BodyPublishers.ofString(form))
                .build();
        var response = httpClient.send(request, BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Bad response from AS: " + response.body());
        }
        return new JSONObject(response.body());
    }

    private static JSONObject pollAccessTokenEndpoint(
            String clientId, String deviceCode) throws Exception {
        var form = "client_id=" + clientId +
                "&grant_type=urn:ietf:params:oauth:grant-type:device_code" +
                "&device_code=" + URLEncoder.encode(deviceCode, UTF_8);

        var request = HttpRequest.newBuilder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .uri(URI.create("https://as.example.com:8443/openam/oauth2/access_token"))
                .POST(BodyPublishers.ofString(form))
                .build();
        var response = httpClient.send(request, BodyHandlers.ofString());
        return new JSONObject(response.body());
    }
}
