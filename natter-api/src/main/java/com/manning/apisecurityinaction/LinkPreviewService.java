package com.manning.apisecurityinaction;

import java.io.IOException;
import java.net.*;
import java.util.Set;

import org.json.JSONObject;
import org.jsoup.*;
import org.jsoup.nodes.Document;
import org.slf4j.*;
import spark.ExceptionHandler;

import static org.jsoup.Connection.Method.GET;
import static spark.Spark.*;

public class LinkPreviewService {
    private static final Logger logger =
            LoggerFactory.getLogger(LinkPreviewService.class);

    public static void main(String...args) {
        afterAfter((request, response) -> {
            response.type("application/json; charset=utf-8");
        });

        var expectedHostNames = Set.of(
                "natter-link-preview-service:4567",
                "natter-link-preview-service.natter-api:4567");
        before((request, response) -> {
            if (!expectedHostNames.contains(request.host())) {
                halt(400);
            }
        });

        get("/preview", (request, response) -> {
            var url = request.queryParams("url");
            var doc = fetch(url);
            var title = doc.title();
            var desc = doc.head()
                    .selectFirst("meta[property='og:description']");
            var img = doc.head()
                    .selectFirst("meta[property='og:image']");

            return new JSONObject()
                    .put("url", doc.location())
                    .putOpt("title", title)
                    .putOpt("description",
                            desc == null ? null : desc.attr("content"))
                    .putOpt("image",
                            img == null ? null : img.attr("content"));
        });

        exception(IllegalArgumentException.class, handleException(400));
        exception(MalformedURLException.class, handleException(400));
        exception(Exception.class, handleException(502));
        exception(UnknownHostException.class, handleException(404));
    }

    private static Document fetch(String url) throws IOException {
        Document doc = null;
        var retries = 0;
        while (doc == null && retries++ < 10) {
            logger.info("Checking URL {}", url);
            if (isBlockedAddress(url)) {
                throw new IllegalArgumentException(
                        "URL refers to local/private address");
            }
            var res = Jsoup.connect(url).followRedirects(false)
                    .timeout(3000).method(GET).execute();
            if (res.statusCode() / 100 == 3) {
                url = res.header("Location");
            } else {
                doc = res.parse();
            }
        }
        if (doc == null) throw new IOException("too many redirects");
        return doc;
    }

    private static boolean isBlockedAddress(String uri)
            throws UnknownHostException {
        var host = URI.create(uri).getHost();
        for (var ipAddr : InetAddress.getAllByName(host)) {
            if (ipAddr.isLoopbackAddress() ||
                    ipAddr.isLinkLocalAddress() ||
                    ipAddr.isSiteLocalAddress() ||
                    ipAddr.isMulticastAddress() ||
                    ipAddr.isAnyLocalAddress() ||
                    isUniqueLocalAddress(ipAddr)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isUniqueLocalAddress(InetAddress ipAddr) {
        return ipAddr instanceof Inet6Address &&
                (ipAddr.getAddress()[0] & 0xFF) == 0xFD &&
                (ipAddr.getAddress()[1] & 0xFF) == 0X00;
    }

    private static <T extends Exception> ExceptionHandler<T>
            handleException(int status) {
        return (ex, request, response) -> {
            logger.error("Caught error {} - returning status {}", ex, status);
            response.status(status);
            response.body(new JSONObject().put("status", status).toString());
        };
    }
}
