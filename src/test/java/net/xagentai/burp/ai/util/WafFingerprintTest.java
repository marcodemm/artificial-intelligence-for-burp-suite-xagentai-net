package net.xagentai.burp.ai.util;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for the static signature matcher. Uses
 * {@link WafFingerprint#detectFromFlat(Map, String, int)} directly so the
 * tests run off-runtime (Montoya's HttpResponse factory is null outside
 * Burp).
 */
final class WafFingerprintTest {

    @Test
    void detectsCloudflareByCfRayHeader() {
        assertEquals("Cloudflare",
                WafFingerprint.detectFromFlat(
                        Map.of("cf-ray", "8a1b2c3d4e5f6a7b-MAD"),
                        "", 403));
    }

    @Test
    void detectsCloudflareByServerHeaderAndBody() {
        assertEquals("Cloudflare",
                WafFingerprint.detectFromFlat(
                        Map.of("server", "cloudflare"),
                        "Attention Required! | Cloudflare", 403));
    }

    @Test
    void detectsAkamaiByTransformedHeader() {
        assertEquals("Akamai",
                WafFingerprint.detectFromFlat(
                        Map.of("x-akamai-transformed", "9 125 0 pmb=mRUM,1"),
                        "", 403));
    }

    @Test
    void detectsAwsCloudFrontByAmzCfId() {
        assertEquals("AWS CloudFront / WAF",
                WafFingerprint.detectFromFlat(
                        Map.of("x-amz-cf-id", "abc123"),
                        "", 403));
    }

    @Test
    void detectsImpervaByXIinfo() {
        assertEquals("Imperva Incapsula",
                WafFingerprint.detectFromFlat(
                        Map.of("x-iinfo", "12-34567890-0 nNNN RT(123) q(0 0 1 -1) r(1 1) U5"),
                        "", 403));
    }

    @Test
    void detectsImpervaByCookie() {
        assertEquals("Imperva Incapsula",
                WafFingerprint.detectFromFlat(
                        Map.of("set-cookie", "visid_incap_123=abc; path=/"),
                        "", 403));
    }

    @Test
    void detectsSucuriById() {
        assertEquals("Sucuri",
                WafFingerprint.detectFromFlat(
                        Map.of("x-sucuri-id", "123"),
                        "", 403));
    }

    @Test
    void detectsF5BigIpByCookie() {
        assertEquals("F5 BIG-IP / ASM",
                WafFingerprint.detectFromFlat(
                        Map.of("set-cookie", "BIGipServerpool_app=rd5o00000000000000000000ffff0a0a0a0ao80"),
                        "", 403));
    }

    @Test
    void detectsModSecurityByBodyText() {
        assertEquals("ModSecurity",
                WafFingerprint.detectFromFlat(
                        Map.of("server", "Apache"),
                        "<html><body>Not Acceptable!</body></html>", 406));
    }

    @Test
    void detectsFortinetByCookie() {
        assertEquals("Fortinet FortiWeb",
                WafFingerprint.detectFromFlat(
                        Map.of("set-cookie", "FORTIWAFSID=abc123"),
                        "", 403));
    }

    @Test
    void detectsFastlyByDebugPath() {
        assertEquals("Fastly",
                WafFingerprint.detectFromFlat(
                        Map.of("fastly-debug-path", "(D cache-mad7363-MAD 1699999999)"),
                        "", 200));
    }

    @Test
    void detectsAzureFrontDoor() {
        assertEquals("Azure Front Door / WAF",
                WafFingerprint.detectFromFlat(
                        Map.of("x-azure-ref", "0abcd1234"),
                        "", 403));
    }

    @Test
    void detectsWordfenceByBodyOnly() {
        assertEquals("Wordfence",
                WafFingerprint.detectFromFlat(
                        Map.of(),
                        "Your access to this site has been limited by the site owner "
                      + "(Wordfence). If you think you have been blocked...", 503));
    }

    @Test
    void fallsBackToStatusHintWhenNothingMatches() {
        assertEquals("Unknown (HTTP 429 suggests WAF, bot-manager or rate-limit)",
                WafFingerprint.detectFromFlat(
                        Map.of("server", "nginx"),
                        "", 429));
    }

    @Test
    void returnsPureUnknownForNormal200() {
        assertEquals(WafFingerprint.UNKNOWN,
                WafFingerprint.detectFromFlat(
                        Map.of("server", "nginx", "content-type", "text/html"),
                        "<html>hello</html>", 200));
    }

    @Test
    void headerLookupIsCaseInsensitive() {
        assertEquals("Cloudflare",
                WafFingerprint.detectFromFlat(
                        Map.of("cf-ray", "foo"),
                        "", 200));
    }

    @Test
    void handlesNullBodyAndNullHeadersGracefully() {
        assertEquals("Unknown (HTTP 403 suggests WAF, bot-manager or rate-limit)",
                WafFingerprint.detectFromFlat(null, null, 403));
    }
}
