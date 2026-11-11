package net.xagentai.burp.ai.util;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Serialize Burp's typed objects (HttpRequestResponse, WebSocketMessage,
 * AuditIssue) into plain text suitable for inclusion in an AI prompt.
 *
 * All output is UTF-8 decoded on a best-effort basis; binary bodies may
 * render as mojibake but structure (headers, status line) stays readable.
 */
public final class HttpRequestSerializer {

    /** Default soft cap on how much we send to the AI (per call, in chars). */
    public static final int DEFAULT_MAX_CHARS = 40_000;

    private HttpRequestSerializer() {}

    // --- HTTP -------------------------------------------------------------

    public static String serialize(HttpRequestResponse rr) {
        return serialize(rr, DEFAULT_MAX_CHARS);
    }

    public static String serialize(HttpRequestResponse rr, int maxChars) {
        if (rr == null) return "";
        StringBuilder sb = new StringBuilder();

        if (rr.url() != null) {
            sb.append("URL: ").append(rr.url()).append("\n\n");
        }

        HttpRequest req = rr.request();
        if (req != null) {
            sb.append("--- REQUEST ---\n");
            sb.append(wire(req.toByteArray()));
            if (!sb.toString().endsWith("\n")) sb.append('\n');
        }

        if (rr.hasResponse()) {
            HttpResponse resp = rr.response();
            if (resp != null) {
                sb.append("\n--- RESPONSE ---\n");
                sb.append(wire(resp.toByteArray()));
            }
        }
        return truncate(sb.toString(), maxChars);
    }

    // --- WebSocket --------------------------------------------------------

    public static String serializeWebSocketMessages(List<WebSocketMessage> messages, int maxChars) {
        if (messages == null || messages.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();

        // Include the upgrade request for context (same for all messages on a stream).
        HttpRequest upgrade = messages.get(0).upgradeRequest();
        if (upgrade != null) {
            sb.append("--- UPGRADE REQUEST ---\n");
            sb.append(wire(upgrade.toByteArray()));
            if (!sb.toString().endsWith("\n")) sb.append('\n');
            sb.append('\n');
        }

        int idx = 1;
        for (WebSocketMessage m : messages) {
            sb.append("--- WS MESSAGE #").append(idx++)
              .append(" (").append(m.direction()).append(") ---\n");
            sb.append(wire(m.payload()));
            if (!sb.toString().endsWith("\n")) sb.append('\n');
            sb.append('\n');
        }
        return truncate(sb.toString(), maxChars);
    }

    // --- Audit issues -----------------------------------------------------

    public static String serializeAuditIssues(List<AuditIssue> issues, int maxChars) {
        if (issues == null || issues.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        int idx = 1;
        for (AuditIssue i : issues) {
            sb.append("--- ISSUE #").append(idx++).append(" ---\n");
            sb.append("Name:       ").append(nonNull(i.name())).append('\n');
            if (i.severity() != null)   sb.append("Severity:   ").append(i.severity()).append('\n');
            if (i.confidence() != null) sb.append("Confidence: ").append(i.confidence()).append('\n');
            if (i.baseUrl() != null)    sb.append("URL:        ").append(i.baseUrl()).append('\n');
            if (i.detail() != null && !i.detail().isBlank()) {
                sb.append("\nDetail:\n").append(stripHtml(i.detail())).append('\n');
            }
            if (i.remediation() != null && !i.remediation().isBlank()) {
                sb.append("\nRemediation:\n").append(stripHtml(i.remediation())).append('\n');
            }
            List<HttpRequestResponse> rrs = i.requestResponses();
            if (rrs != null && !rrs.isEmpty()) {
                sb.append("\n-- Evidence request/response --\n");
                sb.append(serialize(rrs.get(0), Math.max(2000, maxChars / Math.max(1, issues.size()))));
            }
            sb.append("\n\n");
        }
        return truncate(sb.toString(), maxChars);
    }

    // --- helpers ----------------------------------------------------------

    private static String wire(ByteArray ba) {
        if (ba == null) return "";
        return new String(ba.getBytes(), StandardCharsets.UTF_8);
    }

    private static String nonNull(String s) {
        return s == null ? "" : s;
    }

    /** Quick-and-dirty HTML tag strip for Burp's HTML-formatted issue text. */
    private static String stripHtml(String s) {
        if (s == null) return "";
        return s.replaceAll("<[^>]+>", "").replace("&nbsp;", " ")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "\n\n[... truncated to " + max + " chars ...]";
    }
}
