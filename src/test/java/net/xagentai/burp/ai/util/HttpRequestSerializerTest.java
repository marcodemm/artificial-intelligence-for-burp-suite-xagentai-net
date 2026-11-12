package net.xagentai.burp.ai.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpRequestSerializerTest {

    @Test
    void replacesNullByteWithQuestionMark() {
        assertEquals("hello?world",
                HttpRequestSerializer.sanitizeControlChars("hello\u0000world"));
    }

    @Test
    void preservesLineFeedCarriageReturnAndTab() {
        String s = "line1\nline2\r\nline3\ttab";
        assertEquals(s, HttpRequestSerializer.sanitizeControlChars(s),
                "LF, CR and TAB must survive sanitization — Gson escapes them correctly");
    }

    @Test
    void replacesAssortedC0ControlChars() {
        // U+0001 SOH, U+000B VT, U+000E SO, U+001F US — none are escaped by Gson default
        assertEquals("a?b?c?d?e",
                HttpRequestSerializer.sanitizeControlChars("a\u0001b\u000Bc\u000Ed\u001Fe"));
    }

    @Test
    void replacesDelCharacter() {
        assertEquals("?bye",
                HttpRequestSerializer.sanitizeControlChars("\u007Fbye"));
    }

    @Test
    void returnsSameInstanceWhenNothingToClean() {
        String clean = "plain ASCII with\nallowed\twhitespace";
        assertSame(clean, HttpRequestSerializer.sanitizeControlChars(clean),
                "Fast-path: no allocation when the input is already safe");
    }

    @Test
    void handlesNullAndEmpty() {
        assertEquals("", HttpRequestSerializer.sanitizeControlChars(null));
        assertEquals("", HttpRequestSerializer.sanitizeControlChars(""));
    }

    @Test
    void preservesHighUnicodeCharacters() {
        // U+2014 EM DASH is NOT a C0 control char — must survive.
        String s = "1. ENDPOINT — one-line summary";
        String out = HttpRequestSerializer.sanitizeControlChars(s);
        assertTrue(out.contains("—"), "Non-C0 unicode must not be touched");
        assertFalse(out.contains("?"));
    }
}
