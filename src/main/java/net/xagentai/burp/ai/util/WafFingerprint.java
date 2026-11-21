package net.xagentai.burp.ai.util;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Best-effort WAF / CDN fingerprinting from a single HTTP response.
 *
 * <p>Checks response headers (and a few well-known cookies) first, falls back
 * to body-string signatures (challenge pages, block-page markers), and finally
 * to a status-code hint ({@code 403/406/419/429/503}) when nothing else
 * matches but the response still smells like a block.
 *
 * <p>The public entry point {@link #detect(HttpResponse)} is the wrapper for
 * runtime use; the actual logic lives in {@link #detectFromFlat(Map, String,
 * int)} so unit tests can exercise every signature with plain {@code Map}s
 * and strings without instantiating a Montoya {@code HttpResponse} (its
 * factory is {@code null} off-runtime).
 *
 * <p>Signatures are compiled from the 2026 reality of the most-deployed
 * WAFs / CDNs — order matters: CDN-specific headers win over generic
 * "Server:" matches when both are present.
 */
public final class WafFingerprint {

    /** Returned when no signature matches. */
    public static final String UNKNOWN = "Unknown";

    private WafFingerprint() {}

    public static String detect(HttpResponse response) {
        if (response == null) return UNKNOWN;
        String native_ = detectNative(response);
        if (native_ != null && !native_.equals(UNKNOWN) && !native_.startsWith("Unknown (")) {
            // Our native detector already matched one of the 13 strong
            // signatures — prefer it over the broader catalog.
            return native_;
        }
        // Fallback to the identYwaf catalog (~95 WAFs). Build a textual
        // approximation of the raw response so the catalog's regexes have
        // headers and body to look at.
        try {
            String catalog = WafSignatures.get().matchPassive(rawTextOf(response));
            if (catalog != null) return catalog;
        } catch (RuntimeException ignored) {
            // Catalog loading / regex blow-up: fall through to native's fallback.
        }
        return native_;
    }

    /**
     * Native-only detection (13 strong CDN signatures), no catalog fallback.
     * Call this when you want to probe for well-known CDN headers
     * (e.g. {@code Server: cloudflare}, {@code CF-Ray}) that identYwaf's
     * catalog deliberately does NOT match — identYwaf keys WAFs by their
     * block-page text, not by presence of a CDN in the chain.
     */
    public static String detectNative(HttpResponse response) {
        if (response == null) return UNKNOWN;
        Map<String, String> flat = new HashMap<>();
        List<HttpHeader> hs = response.headers();
        if (hs != null) {
            for (HttpHeader h : hs) {
                if (h == null || h.name() == null) continue;
                String key = h.name().toLowerCase();
                String val = h.value() == null ? "" : h.value();
                flat.merge(key, val, (a, b) -> a + "\n" + b);
            }
        }
        String body;
        try {
            body = response.bodyToString();
        } catch (RuntimeException ex) {
            body = "";
        }
        return detectFromFlat(flat, body == null ? "" : body, response.statusCode());
    }

    private static String rawTextOf(HttpResponse response) {
        StringBuilder raw = new StringBuilder();
        List<HttpHeader> hs = response.headers();
        if (hs != null) {
            for (HttpHeader h : hs) {
                if (h == null || h.name() == null) continue;
                raw.append(h.name()).append(": ").append(h.value() == null ? "" : h.value())
                   .append("\r\n");
            }
        }
        raw.append("\r\n");
        try {
            String body = response.bodyToString();
            if (body != null) raw.append(body);
        } catch (RuntimeException ignored) {}
        return raw.toString();
    }

    static String detectFromFlat(Map<String, String> headers, String body, int statusCode) {
        if (headers == null) headers = Map.of();
        if (body == null) body = "";

        // --- CDN / WAF, ordered by signature strength --------------------

        // Cloudflare
        if (hasHeader(headers, "cf-ray") || hasHeader(headers, "cf-cache-status")
                || headerMatches(headers, "server", "^cloudflare")
                || (body.contains("Attention Required!") && body.contains("Cloudflare"))
                || body.contains("Cloudflare Ray ID")) {
            return "Cloudflare";
        }

        // Akamai
        if (hasHeader(headers, "x-akamai-transformed") || hasHeader(headers, "akamai-grn")
                || headerMatches(headers, "server", "AkamaiGHost|AkamaiNetStorage")
                || body.contains("AkamaiGHost")
                || body.contains("Reference&#32;&#35;")) {
            return "Akamai";
        }

        // AWS CloudFront + AWS WAF
        if (hasHeader(headers, "x-amz-cf-id") || hasHeader(headers, "x-amz-cf-pop")
                || headerMatches(headers, "server", "CloudFront|awselb")
                || headerMatches(headers, "x-cache", "cloudfront")
                || (body.contains("Request blocked") && body.contains("awselb"))
                || body.contains("ERROR: The request could not be satisfied")) {
            return "AWS CloudFront / WAF";
        }

        // Imperva Incapsula
        if (hasHeader(headers, "x-iinfo") || headerMatches(headers, "x-cdn", "Incapsula")
                || headerMatches(headers, "set-cookie", "visid_incap|incap_ses|nlbi_")
                || body.contains("Incapsula incident ID")
                || body.contains("_Incapsula_Resource")) {
            return "Imperva Incapsula";
        }

        // Sucuri
        if (headerMatches(headers, "server", "Sucuri")
                || hasHeader(headers, "x-sucuri-id") || hasHeader(headers, "x-sucuri-cache")
                || body.contains("Access Denied - Sucuri")) {
            return "Sucuri";
        }

        // F5 BIG-IP / ASM
        if (headerMatches(headers, "server", "BigIP|BIG-IP")
                || headerMatches(headers, "set-cookie", "BIGipServer|TS[0-9a-f]{8}=")
                || hasHeader(headers, "x-cnection")
                || body.contains("The requested URL was rejected")) {
            return "F5 BIG-IP / ASM";
        }

        // ModSecurity (generic, often with Apache/Nginx)
        if (headerMatches(headers, "server", "Mod_Security|NOYB")
                || body.contains("Mod_Security")
                || body.contains("This error was generated by Mod_Security")
                || body.contains("Not Acceptable!")) {
            return "ModSecurity";
        }

        // Fortinet FortiWeb
        if (headerMatches(headers, "set-cookie", "FORTIWAFSID")
                || body.contains("Blocked by FortiWeb")
                || body.contains("fortinet.com/ns/fortiweb")) {
            return "Fortinet FortiWeb";
        }

        // Barracuda WAF
        if (headerMatches(headers, "set-cookie", "barra_counter_session")
                || headerMatches(headers, "server", "Barracuda")
                || body.contains("blocked by the Barracuda Networks")) {
            return "Barracuda WAF";
        }

        // Fastly
        if (hasHeader(headers, "fastly-debug-path") || hasHeader(headers, "x-fastly-request-id")
                || headerMatches(headers, "x-served-by", "cache-")
                || headerMatches(headers, "via", "varnish.*Fastly")) {
            return "Fastly";
        }

        // Cloudflare's competitor: Google Cloud Armor
        if (headerMatches(headers, "via", "google")
                && (body.contains("blocked by security policy") || body.contains("Google Cloud Armor"))) {
            return "Google Cloud Armor";
        }

        // Azure Front Door / Azure WAF
        if (hasHeader(headers, "x-azure-ref") || headerMatches(headers, "server", "Microsoft-Azure")
                || (body.contains("The request is blocked") && body.contains("Microsoft-Azure"))) {
            return "Azure Front Door / WAF";
        }

        // Wordfence (WordPress plugin firewall) — body-only, no distinctive header
        if (body.contains("Wordfence")
                && (body.contains("blocked") || body.contains("firewall") || body.contains("your access"))) {
            return "Wordfence";
        }

        // Generic status-code hint — no signature, but the status suggests a block
        if (statusCode == 406 || statusCode == 419 || statusCode == 429
                || statusCode == 403 || statusCode == 503) {
            return "Unknown (HTTP " + statusCode + " suggests WAF, bot-manager or rate-limit)";
        }
        return UNKNOWN;
    }

    private static boolean hasHeader(Map<String, String> headers, String name) {
        return headers.containsKey(name.toLowerCase());
    }

    private static boolean headerMatches(Map<String, String> headers, String name, String regex) {
        String v = headers.get(name.toLowerCase());
        if (v == null || v.isEmpty()) return false;
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(v).find();
    }
}
