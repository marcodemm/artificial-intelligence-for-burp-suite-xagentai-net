package net.xagentai.burp.ai.util;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * Minimal JSON-over-HTTP helper used by cloud providers (Claude, OpenAI-compat
 * local servers). Built on the JDK's built-in {@link HttpClient} to avoid any
 * extra runtime dependency.
 */
public final class HttpJson {

    private HttpJson() {}

    public static String post(String url, Map<String, String> headers, String jsonBody, int timeoutSeconds)
            throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(Math.max(5, timeoutSeconds)))
                .build();
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(Math.max(5, timeoutSeconds)))
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8));

        boolean hasContentType = false;
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if ("content-type".equalsIgnoreCase(e.getKey())) hasContentType = true;
                b.header(e.getKey(), e.getValue());
            }
        }
        if (!hasContentType) {
            b.header("Content-Type", "application/json");
        }

        HttpResponse<String> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new IOException("HTTP " + resp.statusCode() + " from " + url + " — " + truncate(resp.body(), 500));
        }
        return resp.body();
    }

    public static String get(String url, Map<String, String> headers, int timeoutSeconds)
            throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(Math.max(5, timeoutSeconds)))
                .build();
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(Math.max(5, timeoutSeconds)))
                .GET();
        if (headers != null) headers.forEach(b::header);

        HttpResponse<String> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new IOException("HTTP " + resp.statusCode() + " from " + url + " — " + truncate(resp.body(), 500));
        }
        return resp.body();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
