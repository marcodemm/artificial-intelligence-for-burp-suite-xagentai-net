package net.xagentai.burp.ai.util;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Smoke tests for the identYwaf catalog loader — just enough to catch
 * regressions in the resource shipping, the CRC + base64 computation of
 * {@link WafSignatures#computeSignature(boolean[])}, and the match
 * fallbacks.
 */
final class WafSignaturesTest {

    @Test
    void catalogLoadsSuccessfully() {
        WafSignatures s = WafSignatures.get();
        assertTrue(s.wafCount() >= 90, "expected ~95 WAFs, got " + s.wafCount());
        assertEquals(45, s.payloadCount(), "identYwaf schema v1 ships 45 payloads");
    }

    @Test
    void everyPayloadHasCategoryAndValue() {
        WafSignatures s = WafSignatures.get();
        for (int i = 0; i < s.payloadCount(); i++) {
            assertNotNull(s.payloadCategory(i), "category missing at " + i);
            assertFalse(s.payloadCategory(i).isBlank(), "blank category at " + i);
            assertNotNull(s.payloadValue(i), "value missing at " + i);
            assertFalse(s.payloadValue(i).isBlank(), "blank value at " + i);
        }
    }

    @Test
    void computeSignatureProducesChecksumColonBase64() {
        WafSignatures s = WafSignatures.get();
        boolean[] blocked = new boolean[s.payloadCount()];
        for (int i = 0; i < blocked.length; i++) blocked[i] = (i % 2 == 0);
        String sig = s.computeSignature(blocked);
        assertTrue(sig.matches("^[0-9a-f]{4}:[A-Za-z0-9+/=]+$"),
                "signature format should be hhhh:base64 — got " + sig);
        // Decoded blob is exactly 2 bytes per payload.
        byte[] decoded = Base64.getDecoder().decode(sig.substring(5));
        assertEquals(2 * s.payloadCount(), decoded.length);
    }

    @Test
    void sameVectorYieldsSameSignature() {
        WafSignatures s = WafSignatures.get();
        boolean[] v = new boolean[s.payloadCount()];
        for (int i = 0; i < v.length; i++) v[i] = (i < 10);
        assertEquals(s.computeSignature(v), s.computeSignature(v));
    }

    @Test
    void differentVectorsYieldDifferentSignatures() {
        WafSignatures s = WafSignatures.get();
        boolean[] a = new boolean[s.payloadCount()];
        boolean[] b = new boolean[s.payloadCount()];
        for (int i = 0; i < a.length; i++) {
            a[i] = true;
            b[i] = (i % 3 == 0);
        }
        assertNotEquals(s.computeSignature(a), s.computeSignature(b));
    }

    @Test
    void matchBlindReturnsEmptyForAllFalseVector() {
        WafSignatures s = WafSignatures.get();
        boolean[] none = new boolean[s.payloadCount()];
        LinkedHashMap<String, Integer> m = s.matchBlind(none);
        // identYwaf declines to partial-match a vector that has fewer than
        // 5 blocked payloads — the score becomes noise. Empty expected.
        assertTrue(m.isEmpty(), "all-false vector should produce no matches; got " + m);
    }

    @Test
    void matchBlindSuppressesPartialWhenFewBlocked() {
        WafSignatures s = WafSignatures.get();
        // 3 blocked out of 45 — below MIN_MATCH_PARTIAL (5), the matcher
        // should return an empty map so the UI doesn't present confident
        // but meaningless "WebSEAL 96%" suggestions on near-empty vectors.
        boolean[] few = new boolean[s.payloadCount()];
        few[0] = true; few[20] = true; few[21] = true;
        assertTrue(s.matchBlind(few).isEmpty(),
                "fewer than 5 blocked payloads must not emit partial matches");
    }

    @Test
    void matchBlindEmitsPartialWhenEnoughBlocked() {
        WafSignatures s = WafSignatures.get();
        // At or above MIN_MATCH_PARTIAL, partial match IS allowed.
        boolean[] many = new boolean[s.payloadCount()];
        for (int i = 0; i < 10; i++) many[i] = true;
        assertFalse(s.matchBlind(many).isEmpty(),
                "10 blocked payloads should produce at least one partial match");
    }

    @Test
    void matchPassiveDetectsCloudflareFromRealisticResponse() {
        String raw = "Server: cloudflare\r\n"
                + "CF-RAY: 1234567890abcdef-MAD\r\n"
                + "Content-Type: text/html\r\n\r\n"
                + "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title>"
                + "</head><body>...Cloudflare Ray ID: 1234...</body></html>";
        String match = WafSignatures.get().matchPassive(raw);
        assertNotNull(match, "should have matched Cloudflare from the raw");
        assertTrue(match.toLowerCase().contains("cloud"),
                "match should contain 'cloud' — got " + match);
    }

    @Test
    void pythonInlineFlagsAreMovedToJavaFlags() {
        Pattern p = WafSignatures.compilePythonFlagRegex("(?i)abc(?s).*def");
        assertTrue(p.matcher("ABC\n\nDEF").find(), "should match case-insensitive + DOTALL");
        assertEquals(Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL,
                p.flags() & (Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL));
    }

    @Test
    void crc16MatchesPythonZlibCrc32LowBits() {
        // Known CRC-32/IEEE value of "hello": 0x3610A686 → low 16 bits = 0xA686
        int v = WafSignatures.crc16("hello".getBytes());
        assertEquals(0xA686, v);
    }

    @Test
    void allWafDisplayNamesReportsEveryEntry() {
        WafSignatures s = WafSignatures.get();
        List<String> names = s.allWafDisplayNames();
        assertEquals(s.wafCount(), names.size());
        assertTrue(names.stream().anyMatch(n -> n.toLowerCase().contains("cloudflare")),
                "catalog should include Cloudflare — got " + names);
    }
}
