package net.xagentai.burp.ai.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.IOException;
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

        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withBody(jsonBody);

        boolean hasContentType = false;
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if ("content-type".equalsIgnoreCase(e.getKey())) {
                    hasContentType = true;
                }
                req = req.withUpdatedHeader(e.getKey(), e.getValue());
            }
        }
        if (!hasContentType) {
            req = req.withUpdatedHeader("Content-Type", "application/json");
        }

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
                req = req.withUpdatedHeader(e.getKey(), e.getValue());
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
}
