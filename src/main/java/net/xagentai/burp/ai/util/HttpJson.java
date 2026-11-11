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
        // Content-Length is required for POST; make sure it matches the
        // actual UTF-8 byte count we're shipping (Burp may add it from the
        // String length, which is wrong for multi-byte UTF-8 chars like '—').
        req = setHeader(req, "Content-Length", Integer.toString(bodyBytes.length));

        // Diagnostic log — remove once the HTTP 400 "control character"
        // issue is fully nailed down.
        api.logging().logToOutput("[HttpJson.post] url=" + url
                + " jsonLen(chars)=" + jsonBody.length()
                + " bodyLen(utf8-bytes)=" + bodyBytes.length);
        int center = Math.min(239, jsonBody.length());
        int lo = Math.max(0, center - 20);
        int hi = Math.min(jsonBody.length(), center + 20);
        StringBuilder hex = new StringBuilder();
        StringBuilder txt = new StringBuilder();
        for (int i = lo; i < hi; i++) {
            char c = jsonBody.charAt(i);
            hex.append(String.format("%04X ", (int) c));
            txt.append((c < 0x20 || c > 0x7E) ? '.' : c);
        }
        api.logging().logToOutput("[HttpJson.post] chars[" + lo + "-" + hi
                + "] hex=" + hex.toString().trim());
        api.logging().logToOutput("[HttpJson.post] chars[" + lo + "-" + hi
                + "] txt=" + txt);

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
        String body = rr.response().bodyToString();
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
        String body = rr.response().bodyToString();
        if (status / 100 != 2) {
            throw new IOException("HTTP " + status + " from " + url + " — " + truncate(body, 500));
        }
        return body;
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
