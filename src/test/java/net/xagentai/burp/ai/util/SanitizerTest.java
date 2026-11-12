package net.xagentai.burp.ai.util;

import net.xagentai.burp.ai.config.ProviderKind;
import net.xagentai.burp.ai.config.SanitizationMode;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SanitizerTest {

    @Test
    void redactsAuthorizationValueAndKeepsHeaderName() {
        String in = "GET /x HTTP/1.1\r\n"
                  + "Host: example.com\r\n"
                  + "Authorization: Bearer abc.def.ghi\r\n"
                  + "\r\n";
        String out = Sanitizer.redactHeaders(in);
        assertTrue(out.contains("Authorization: " + Sanitizer.REDACTED),
                "Authorization value must be replaced with [REDACTED]");
        assertFalse(out.contains("abc.def.ghi"),
                "Original token must not appear in the sanitized output");
        assertTrue(out.contains("Host: example.com"),
                "Non-sensitive headers must be left intact");
    }

    @Test
    void headerMatchIsCaseInsensitive() {
        String in = "GET / HTTP/1.1\r\nAUTHORIZATION: secret\r\n\r\n";
        String out = Sanitizer.redactHeaders(in);
        assertTrue(out.contains("AUTHORIZATION: " + Sanitizer.REDACTED),
                "Header name casing must not affect redaction");
        assertFalse(out.contains("secret"));
    }

    @Test
    void redactsEveryListedHeader() {
        String in = "POST /x HTTP/1.1\r\n"
                  + "Host: example.com\r\n"
                  + "Authorization: a\r\n"
                  + "Proxy-Authorization: b\r\n"
                  + "Cookie: c\r\n"
                  + "Set-Cookie: d\r\n"
                  + "X-Api-Key: e\r\n"
                  + "X-Auth-Token: f\r\n"
                  + "X-Amz-Security-Token: g\r\n"
                  + "X-CSRF-Token: h\r\n"
                  + "\r\nbody";
        String out = Sanitizer.redactHeaders(in);
        for (String letter : new String[]{"a", "b", "c", "d", "e", "f", "g", "h"}) {
            assertFalse(out.contains(": " + letter + "\r\n"),
                    "Sensitive value '" + letter + "' must not survive sanitization");
        }
        assertTrue(out.endsWith("body"),
                "Body after the blank line must be preserved verbatim");
    }

    @Test
    void doesNotTouchUnrelatedHeaders() {
        String in = "GET / HTTP/1.1\r\n"
                  + "Content-Type: application/json\r\n"
                  + "Accept: */*\r\n"
                  + "User-Agent: XagentAI/test\r\n"
                  + "\r\n";
        assertEquals(in, Sanitizer.redactHeaders(in),
                "A message with no sensitive headers must come back byte-identical");
    }

    @Test
    void shouldRedactMatrix() {
        assertTrue(Sanitizer.shouldRedact(SanitizationMode.ACTIVE, ProviderKind.CLOUD));
        assertTrue(Sanitizer.shouldRedact(SanitizationMode.ACTIVE, ProviderKind.LOCAL));
        assertFalse(Sanitizer.shouldRedact(SanitizationMode.INACTIVE, ProviderKind.CLOUD));
        assertFalse(Sanitizer.shouldRedact(SanitizationMode.INACTIVE, ProviderKind.LOCAL));
        // AUTO is the whole point: redact only when leaving the machine.
        assertTrue(Sanitizer.shouldRedact(SanitizationMode.AUTO, ProviderKind.CLOUD));
        assertFalse(Sanitizer.shouldRedact(SanitizationMode.AUTO, ProviderKind.LOCAL));
    }
}
