package net.xagentai.burp.ai.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Minimal JSON-over-HTTP helper routed through Burp's own HTTP stack
 * ({@link burp.api.montoya.http.Http#sendRequest}). Going through Burp
 * means outbound AI calls honour upstream proxy, TLS and session-handling
 * rules configured in the user's Burp, as recommended by criterion #7 of
 * the BApp Store acceptance criteria.
 */
public final class HttpJson {

    private HttpJson() {}

    public static String post(MontoyaApi api,
                              String url,
                              Map<String, String> headers,
                              String jsonBody,
                              int timeoutSeconds) throws IOException {

        // Explicit UTF-8 → ByteArray avoids any ambiguity about what
        // charset Montoya's withBody(String) overload uses to encode the
        // JSON body. Burp sees exactly the bytes we hand it.
        byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);

        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withBody(ByteArray.byteArray(bodyBytes));

        boolean hasContentType = false;
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if ("content-type".equalsIgnoreCase(e.getKey())) {
                    hasContentType = true;
                }
                req = setHeader(req, e.getKey(), e.getValue());
            }
        }
        if (!hasContentType) {
            req = setHeader(req, "Content-Type", "application/json");
        }
        // Content-Length must match the actual UTF-8 byte count: Java's
        // String.length() returns UTF-16 code units, which under-counts
        // multi-byte characters like U+2014 EM DASH.
        req = setHeader(req, "Content-Length", Integer.toString(bodyBytes.length));

        RequestOptions opts = RequestOptions.requestOptions()
                .withResponseTimeout(Math.max(5, timeoutSeconds) * 1000L);

        HttpRequestResponse rr;
        try {
            rr = api.http().sendRequest(req, opts);
        } catch (RuntimeException ex) {
            // Burp wraps low-level network issues as RuntimeException.
            throw new IOException("Request to " + url + " failed: " + ex.getMessage(), ex);
        }
        if (!rr.hasResponse()) {
            throw new IOException("No response from " + url);
        }
        int status = rr.response().statusCode();
        String body = utf8Body(rr);
        if (status / 100 != 2) {
            throw new IOException("HTTP " + status + " from " + url + " — " + truncate(body, 500));
        }
        return body;
    }

    public static String get(MontoyaApi api,
                             String url,
                             Map<String, String> headers,
                             int timeoutSeconds) throws IOException {

        HttpRequest req = HttpRequest.httpRequestFromUrl(url);
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                req = setHeader(req, e.getKey(), e.getValue());
            }
        }

        RequestOptions opts = RequestOptions.requestOptions()
                .withResponseTimeout(Math.max(5, timeoutSeconds) * 1000L);

        HttpRequestResponse rr;
        try {
            rr = api.http().sendRequest(req, opts);
        } catch (RuntimeException ex) {
            throw new IOException("Request to " + url + " failed: " + ex.getMessage(), ex);
        }
        if (!rr.hasResponse()) {
            throw new IOException("No response from " + url);
        }
        int status = rr.response().statusCode();
        String body = utf8Body(rr);
        if (status / 100 != 2) {
            throw new IOException("HTTP " + status + " from " + url + " — " + truncate(body, 500));
        }
        return body;
    }

    /**
     * Decode the response body explicitly as UTF-8. Montoya's
     * {@code response().bodyToString()} relies on the Content-Type charset
     * heuristic and falls back to ISO-8859-1 when the server omits it,
     * which produced mojibake ('â', 'â€', 'â€™') for providers like
     * NVIDIA that don't declare the charset in Content-Type. Every
     * AI provider we talk to returns JSON, which is UTF-8 per RFC 8259.
     */
    private static String utf8Body(HttpRequestResponse rr) {
        burp.api.montoya.core.ByteArray body = rr.response().body();
        return new String(body.getBytes(), StandardCharsets.UTF_8);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    /**
     * Upsert a header: {@code withUpdatedHeader} silently no-ops when the
     * header is absent, so we add it in that case and update it otherwise.
     * This is the root cause of the "x-api-key header is required" bug we
     * hit after migrating off the JDK HttpClient.
     */
    private static HttpRequest setHeader(HttpRequest req, String name, String value) {
        if (req.hasHeader(name)) {
            return req.withUpdatedHeader(name, value);
        }
        return req.withAddedHeader(name, value);
    }
}
