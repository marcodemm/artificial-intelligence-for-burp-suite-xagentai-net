package net.xagentai.burp.ai.util;

import net.xagentai.burp.ai.config.ProviderKind;
import net.xagentai.burp.ai.config.SanitizationMode;

import java.util.Locale;
import java.util.Set;

/**
 * Level-A PII sanitizer: replaces the VALUE of well-known sensitive
 * headers with {@code [REDACTED]} before a request/response is sent to
 * the AI provider. The header NAMES remain so the model still sees
 * "there was an Authorization header".
 *
 * Nothing in the body or query string is touched at this level. That
 * belongs to Level B/C, planned for v1.0.
 */
public final class Sanitizer {

    /** Headers whose values are replaced with [REDACTED]. Compared case-insensitively. */
    public static final Set<String> SENSITIVE_HEADERS = Set.of(
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-auth-token",
            "x-amz-security-token",
            "x-csrf-token"
    );

    public static final String REDACTED = "[REDACTED]";

    private Sanitizer() {}

    /**
     * Decide whether to redact given the user-selected mode and the active
     * provider kind. For {@link SanitizationMode#AUTO}, redaction runs only
     * when the provider is CLOUD.
     */
    public static boolean shouldRedact(SanitizationMode mode, ProviderKind providerKind) {
        return switch (mode) {
            case ACTIVE -> true;
            case INACTIVE -> false;
            case AUTO -> providerKind == ProviderKind.CLOUD;
        };
    }

    /**
     * Redact sensitive header values in a raw HTTP message (request or response
     * in wire format). Only the header block is touched; the body is left
     * untouched. Both CRLF and LF line endings are accepted on input; CRLF is
     * emitted on output within the header block.
     */
    public static String redactHeaders(String rawHttpMessage) {
        if (rawHttpMessage == null || rawHttpMessage.isEmpty()) {
            return rawHttpMessage;
        }

        // Find the header/body boundary.
        int boundary = rawHttpMessage.indexOf("\r\n\r\n");
        int boundaryLen = 4;
        if (boundary < 0) {
            boundary = rawHttpMessage.indexOf("\n\n");
            boundaryLen = 2;
        }

        String headerPart;
        String bodyPart;
        if (boundary < 0) {
            headerPart = rawHttpMessage;
            bodyPart = "";
        } else {
            headerPart = rawHttpMessage.substring(0, boundary);
            bodyPart = rawHttpMessage.substring(boundary); // keeps the blank line + body
        }

        StringBuilder out = new StringBuilder(headerPart.length());
        String[] lines = headerPart.split("\r?\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (i == 0) {
                // Request / status line — leave it alone.
                out.append(line);
            } else {
                int colon = line.indexOf(':');
                if (colon <= 0) {
                    out.append(line);
                } else {
                    String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                    if (SENSITIVE_HEADERS.contains(name)) {
                        out.append(line, 0, colon + 1).append(' ').append(REDACTED);
                    } else {
                        out.append(line);
                    }
                }
            }
            if (i < lines.length - 1) {
                out.append("\r\n");
            }
        }

        return out.toString() + bodyPart;
    }
}
