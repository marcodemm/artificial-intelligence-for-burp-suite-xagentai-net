package net.xagentai.burp.ai.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.IntConsumer;

/**
 * Port of identYwaf's active-probing logic adapted to the Burp Montoya API.
 * Sends identYwaf's 45 crafted payloads (SQLi, XSS, XXE, LDAPi, traversal,
 * …) one at a time through {@code api.http().sendRequest()}, under the same
 * randomly-named query parameter, and classifies each response as blocked
 * or not by comparing it to a baseline request with an innocuous value.
 *
 * <p>Output is a {@link ProbeResult} that carries:
 * <ul>
 *   <li>the {@code boolean[] blocked} vector (fed to
 *       {@link WafSignatures#matchBlind(boolean[])} to identify the WAF),</li>
 *   <li>per-payload details for the UI table, and</li>
 *   <li>any passive catalog matches that triggered on the way.</li>
 * </ul>
 *
 * <p>Rate-limited to the caller's {@code delayMs} (defaults to 500 ms, i.e.
 * 2 requests per second, so the probe does not trip the target's own
 * rate limiter). Every sleep and request is interruptible via the
 * {@code cancelFlag}, so the operator can abort from a waiting dialog
 * without leaving the worker thread spinning.
 *
 * <p>All HTTP traffic goes through Burp's native HTTP stack — upstream
 * proxy, TLS and session-handling settings are honoured; nothing is
 * logged outside the extension's own Output tab.
 *
 * <p>Based on {@code identYwaf.py} (MIT, Copyright 2019-2026 Miroslav
 * Stampar). See {@code NOTICE-identywaf.txt} at the repository root.
 */
public final class ActiveWafProber {

    /** Same list identYwaf scans for in response bodies to detect a block. */
    private static final String[] PROTECTION_KEYWORDS = {
            "rejected", "forbidden", "suspicious", "malicious", "captcha",
            "invalid", "your ip", "please contact", "terminated", "protected",
            "unauthorized", "blocked", "protection", "incident", "denied",
            "detected", "dangerous", "firewall", "fw_block", "unusual activity",
            "bad request", "request id", "injection", "permission",
            "not acceptable", "security policy", "security reasons"
    };

    /** Characters used for the random parameter name — URL-safe, no collisions. */
    private static final String PARAM_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private static final SecureRandom RNG = new SecureRandom();

    private ActiveWafProber() {}

    /**
     * Run the full probe.
     *
     * @param api        Burp Montoya API (for {@code api.http().sendRequest()})
     * @param original   the request the operator selected; path, host, method,
     *                   cookies and auth headers are preserved verbatim
     * @param delayMs    sleep between consecutive probes (>=0; 500 = 2 req/s)
     * @param cancelFlag flipped by the UI when the operator cancels; polled
     *                   before every send and between sleeps
     * @param progress   callback invoked after each probe with the 1-based
     *                   count of probes completed (useful for a progress bar)
     * @return populated result (with {@code cancelled=true} if the operator
     *         aborted mid-run)
     */
    /**
     * HTTP status codes that an operator would read as an explicit block
     * (as opposed to a generic 4xx rejection by the application itself).
     * Package-private for tests.
     */
    static boolean isExplicitBlockStatus(int status) {
        return status == 403 || status == 406 || status == 429
                || status == 451 || status == 503;
    }

    public static ProbeResult probe(MontoyaApi api,
                                    HttpRequest original,
                                    int delayMs,
                                    AtomicBoolean cancelFlag,
                                    IntConsumer progress) {
        WafSignatures sigs = WafSignatures.get();
        int n = sigs.payloadCount();
        boolean[] blocked = new boolean[n];
        List<ProbeDetail> details = new ArrayList<>(n);
        Set<String> passive = new LinkedHashSet<>();

        // Use the SAME random parameter name for every request (baseline +
        // probes) so the server sees a consistent single-parameter surface.
        String param = randomParamName();

        // --- Baseline (two consecutive benign requests) -----------------
        // We send two baselines with different benign values. If they
        // return the same status we trust the baseline; otherwise the
        // endpoint is unstable and we flag the result as "baselineReliable
        // = false" so the operator knows the blocked-vector is noisy.
        //
        // Even a *consistent* baseline is flagged unreliable when the
        // status is itself an error (4xx/5xx) — the "status != baseline"
        // heuristic degenerates in that case (any change away from the
        // error reads as blocked), so we switch to a stricter rule for
        // the probes below.
        HttpRequestResponse b1 = send(api, original, param, randomBenignValue(), cancelFlag);
        if (b1 == null || !b1.hasResponse() || b1.response() == null) {
            return new ProbeResult(blocked, details, -1, 0, new ArrayList<>(passive),
                    1, false, false, false);
        }
        int baselineStatus = b1.response().statusCode();
        int baselineLen = safeBodyLen(b1.response());
        collectPassive(b1.response(), sigs, passive);
        int total = 1;

        if (cancelFlag.get()) {
            return new ProbeResult(blocked, details, baselineStatus, baselineLen,
                    new ArrayList<>(passive), total, true, true, false);
        }
        if (delayMs > 0) {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return new ProbeResult(blocked, details, baselineStatus, baselineLen,
                        new ArrayList<>(passive), total, true, true, false);
            }
        }
        HttpRequestResponse b2 = send(api, original, param, randomBenignValue(), cancelFlag);
        total++;
        boolean baselineConsistent = b2 != null && b2.hasResponse() && b2.response() != null
                && b2.response().statusCode() == baselineStatus;
        if (b2 != null && b2.hasResponse() && b2.response() != null) {
            collectPassive(b2.response(), sigs, passive);
        }
        boolean baselineIsError = baselineStatus >= 400;
        boolean baselineReliable = baselineConsistent && !baselineIsError;

        // --- Probes -------------------------------------------------------
        for (int i = 0; i < n; i++) {
            if (cancelFlag.get()) {
                return new ProbeResult(blocked, details, baselineStatus, baselineLen,
                        new ArrayList<>(passive), total, true, true, baselineReliable);
            }
            if (delayMs > 0) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return new ProbeResult(blocked, details, baselineStatus, baselineLen,
                            new ArrayList<>(passive), total, true, true, baselineReliable);
                }
            }

            String value = sigs.payloadValue(i);
            String category = sigs.payloadCategory(i);
            HttpRequestResponse rr = send(api, original, param, value, cancelFlag);
            total++;
            if (rr == null || !rr.hasResponse() || rr.response() == null) {
                details.add(new ProbeDetail(i, category, value, -1, -1, false,
                        "network error or no response"));
                if (progress != null) progress.accept(i + 1);
                continue;
            }
            HttpResponse resp = rr.response();
            int status = resp.statusCode();
            int bodyLen = safeBodyLen(resp);
            String bodyLower = bodyLowerForKeywordScan(resp);
            String keywordHit = firstKeywordHit(bodyLower);

            boolean wasBlocked;
            String reason;
            if (baselineIsError) {
                // Baseline is already an error — "status != baseline" is
                // meaningless (the server rejecting a malformed param with
                // a different 4xx is NOT a WAF block). Require a strong
                // signal: explicit block status OR a protection keyword.
                boolean explicitBlock = isExplicitBlockStatus(status);
                wasBlocked = explicitBlock || keywordHit != null;
                if (explicitBlock && keywordHit != null) {
                    reason = "explicit block status " + status
                            + " + keyword '" + keywordHit + "' (baseline is error "
                            + baselineStatus + ")";
                } else if (explicitBlock) {
                    reason = "explicit block status " + status
                            + " (baseline is error " + baselineStatus + ")";
                } else if (keywordHit != null) {
                    reason = "protection keyword '" + keywordHit
                            + "' (baseline is error " + baselineStatus + ")";
                } else {
                    reason = "no block signal — status " + status
                            + " ignored because baseline is already " + baselineStatus;
                }
            } else {
                // Baseline is 2xx/3xx — any status change OR keyword hit counts.
                boolean statusDiff = status != baselineStatus;
                wasBlocked = statusDiff || keywordHit != null;
                if (statusDiff && keywordHit != null) {
                    reason = "status " + status + " (baseline " + baselineStatus
                            + ") + keyword '" + keywordHit + "'";
                } else if (statusDiff) {
                    reason = "status " + status + " (baseline " + baselineStatus + ")";
                } else if (keywordHit != null) {
                    reason = "protection keyword '" + keywordHit + "'";
                } else {
                    reason = "no block signal";
                }
            }
            blocked[i] = wasBlocked;
            details.add(new ProbeDetail(i, category, value, status, bodyLen, wasBlocked, reason));
            collectPassive(resp, sigs, passive);
            if (progress != null) progress.accept(i + 1);
        }

        return new ProbeResult(blocked, details, baselineStatus, baselineLen,
                new ArrayList<>(passive), total, false, true, baselineReliable);
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    private static HttpRequestResponse send(MontoyaApi api, HttpRequest original,
                                            String paramName, String paramValue,
                                            AtomicBoolean cancelFlag) {
        if (cancelFlag.get()) return null;
        try {
            HttpRequest req = original.withAddedParameters(
                    HttpParameter.urlParameter(paramName, paramValue));
            return api.http().sendRequest(req);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    /** Lowercased body prefix for the keyword scan; we cap at 32 KiB to stay fast. */
    private static String bodyLowerForKeywordScan(HttpResponse resp) {
        try {
            String body = resp.bodyToString();
            if (body == null) return "";
            if (body.length() > 32768) body = body.substring(0, 32768);
            return body.toLowerCase(java.util.Locale.ROOT);
        } catch (RuntimeException ex) {
            return "";
        }
    }

    private static String firstKeywordHit(String bodyLower) {
        if (bodyLower == null || bodyLower.isEmpty()) return null;
        for (String k : PROTECTION_KEYWORDS) {
            if (bodyLower.contains(k)) return k;
        }
        return null;
    }

    private static int safeBodyLen(HttpResponse resp) {
        try {
            return resp.body().length();
        } catch (RuntimeException ex) {
            return -1;
        }
    }

    private static void collectPassive(HttpResponse resp, WafSignatures sigs,
                                       Set<String> into) {
        // (1) Our native 13-WAF detector — covers CDNs by their header
        //     signatures (Server: cloudflare, CF-Ray, X-Akamai-*, X-Amz-Cf-Id,
        //     X-Iinfo, etc.), which identYwaf's catalog deliberately skips
        //     because identYwaf keys WAFs by their block-page text, not by
        //     presence of a CDN in the chain.
        try {
            String n = WafFingerprint.detectNative(resp);
            if (n != null && !n.equals(WafFingerprint.UNKNOWN)
                    && !n.startsWith("Unknown (")) {
                into.add(n);
            }
        } catch (RuntimeException ignored) {}

        // (2) identYwaf catalog — regex over the whole raw response, catches
        //     WAFs by their distinctive block-page markers ("Attention
        //     Required! | Cloudflare", "Not Acceptable!", "Request blocked",
        //     "Incapsula incident ID", etc.).
        try {
            StringBuilder raw = new StringBuilder();
            List<HttpHeader> hs = resp.headers();
            if (hs != null) {
                for (HttpHeader h : hs) {
                    if (h == null || h.name() == null) continue;
                    raw.append(h.name()).append(": ")
                       .append(h.value() == null ? "" : h.value()).append("\r\n");
                }
            }
            raw.append("\r\n");
            String body = resp.bodyToString();
            if (body != null) raw.append(body.length() > 65536 ? body.substring(0, 65536) : body);
            String match = sigs.matchPassive(raw.toString());
            if (match != null) into.add(match);
        } catch (RuntimeException ignored) {}
    }

    private static String randomParamName() {
        // identYwaf uses short random names; 6-8 chars is enough to avoid
        // collisions with real params and keeps logs readable.
        int len = 6 + RNG.nextInt(3);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(PARAM_ALPHABET.charAt(RNG.nextInt(PARAM_ALPHABET.length())));
        }
        return sb.toString();
    }

    private static String randomBenignValue() {
        int len = 4 + RNG.nextInt(5);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(PARAM_ALPHABET.charAt(RNG.nextInt(PARAM_ALPHABET.length())));
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------------
    // DTOs
    // ---------------------------------------------------------------------

    public static final class ProbeResult {
        public final boolean[] blocked;          // length = payloadCount
        public final List<ProbeDetail> details;
        public final int baselineStatus;         // -1 when baseline failed
        public final int baselineBodyLen;        // -1 when unavailable
        public final List<String> passiveMatches;
        public final int totalRequests;          // baseline + probes actually sent
        public final boolean cancelled;
        public final boolean baselineOk;
        /**
         * {@code true} when the two baselines agreed AND the status was NOT
         * itself a 4xx/5xx. When {@code false}, the result dialog should
         * warn: a 4xx baseline degrades the "status != baseline" heuristic,
         * and inconsistent baselines mean the endpoint is non-deterministic.
         * The prober already switches to a stricter rule when the baseline
         * is an error, but the operator still deserves the heads-up.
         */
        public final boolean baselineReliable;

        ProbeResult(boolean[] blocked, List<ProbeDetail> details,
                    int baselineStatus, int baselineBodyLen,
                    List<String> passiveMatches, int totalRequests,
                    boolean cancelled, boolean baselineOk,
                    boolean baselineReliable) {
            this.blocked = blocked;
            this.details = Collections.unmodifiableList(details);
            this.baselineStatus = baselineStatus;
            this.baselineBodyLen = baselineBodyLen;
            this.passiveMatches = Collections.unmodifiableList(passiveMatches);
            this.totalRequests = totalRequests;
            this.cancelled = cancelled;
            this.baselineOk = baselineOk;
            this.baselineReliable = baselineReliable;
        }

        public int blockedCount() {
            int n = 0;
            for (boolean b : blocked) if (b) n++;
            return n;
        }

        /** 0-100 "hardness" — identYwaf's label for how much the WAF blocks. */
        public int hardnessPct() {
            if (blocked.length == 0) return 0;
            return 100 * blockedCount() / blocked.length;
        }

        public String hardnessLabel() {
            int h = hardnessPct();
            if (h >= 80) return "insane";
            if (h >= 50) return "hard";
            if (h >= 30) return "moderate";
            return "easy";
        }

        /** Categories that were blocked at least once. */
        public List<String> blockedCategories() {
            Set<String> out = new LinkedHashSet<>();
            for (ProbeDetail d : details) if (d.blocked) out.add(d.category);
            return new ArrayList<>(out);
        }

        @Override
        public String toString() {
            return "ProbeResult{baseline=" + baselineStatus
                    + ", blocked=" + blockedCount() + "/" + blocked.length
                    + ", hardness=" + hardnessLabel() + " (" + hardnessPct() + "%)"
                    + ", passive=" + passiveMatches
                    + ", total=" + totalRequests
                    + ", cancelled=" + cancelled + "}";
        }
    }

    public static final class ProbeDetail {
        public final int payloadIndex;
        public final String category;
        public final String payload;
        public final int statusCode;
        public final int bodyLen;
        public final boolean blocked;
        public final String reason;

        ProbeDetail(int payloadIndex, String category, String payload,
                    int statusCode, int bodyLen, boolean blocked, String reason) {
            this.payloadIndex = payloadIndex;
            this.category = category;
            this.payload = payload;
            this.statusCode = statusCode;
            this.bodyLen = bodyLen;
            this.blocked = blocked;
            this.reason = reason;
        }
    }

    // --- Static view helpers --------------------------------------------

    /** Short line summarising blocked payload categories, e.g. "SQLi × 12, XSS × 3". */
    public static String categorySummary(List<ProbeDetail> details) {
        java.util.Map<String, Integer> count = new java.util.LinkedHashMap<>();
        for (ProbeDetail d : details) {
            if (!d.blocked) continue;
            count.merge(d.category, 1, Integer::sum);
        }
        if (count.isEmpty()) return "none";
        StringBuilder sb = new StringBuilder();
        for (var e : count.entrySet()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(e.getKey()).append(" × ").append(e.getValue());
        }
        return sb.toString();
    }

    /** List of payload categories in the catalog (in insertion order). */
    public static List<String> catalogCategories() {
        WafSignatures sigs = WafSignatures.get();
        Set<String> out = new LinkedHashSet<>();
        for (int i = 0; i < sigs.payloadCount(); i++) out.add(sigs.payloadCategory(i));
        return new ArrayList<>(out);
    }

    /** Utility for tests: list of (category, count) pairs. */
    public static List<int[]> catalogCategoryCounts() {
        WafSignatures sigs = WafSignatures.get();
        java.util.LinkedHashMap<String, int[]> m = new java.util.LinkedHashMap<>();
        for (int i = 0; i < sigs.payloadCount(); i++) {
            m.computeIfAbsent(sigs.payloadCategory(i), k -> new int[]{0})[0]++;
        }
        List<int[]> out = new ArrayList<>(m.size());
        for (var e : m.entrySet()) out.add(new int[]{Arrays.hashCode(e.getKey().toCharArray()), e.getValue()[0]});
        return out;
    }
}
