package net.xagentai.burp.ai.util;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.CRC32;

/**
 * Lazy-loaded catalog of WAF signatures from identYwaf
 * (https://github.com/stamparm/identYwaf — MIT, Copyright 2019-2026
 * Miroslav Stampar). The source JSON ships as
 * {@code /identywaf-data.json} inside the JAR; see
 * {@code NOTICE-identywaf.txt} at the repository root for the full MIT
 * notice as required by the license.
 *
 * <p>Two match modes are exposed:
 * <ul>
 *   <li>{@link #matchPassive(String)} — regex against a single raw response
 *       (headers + body). This is the same technique as our native
 *       {@link WafFingerprint} but driven by identYwaf's 95-WAF catalog, so
 *       it works as a second-chance fallback.</li>
 *   <li>{@link #matchBlind(boolean[])} — identYwaf's blind-inference
 *       algorithm: given the {@code blocked[]} vector returned by
 *       {@link ActiveWafProber}, compute the {@code checksum:base64}
 *       signature and look it up (exact match), then fall back to a
 *       partial match that reports percentage confidence per WAF.</li>
 * </ul>
 *
 * <p>Thread-safe: the singleton is initialised once under a lock, and
 * every accessor returns immutable views.
 */
public final class WafSignatures {

    private static volatile WafSignatures instance;

    /** CATEGORY::VALUE strings, exactly as identYwaf stores them. */
    private final List<String> payloadsRaw;
    /** Just the VALUE part of each entry above (what we send). */
    private final List<String> payloadValues;
    /** Just the CATEGORY part — used for the UI summary. */
    private final List<String> payloadCategories;
    /** Precomputed marker per payload: {@code (crc32(payload) << 1) & 0xffff}. */
    private final int[] markers;
    /** WAF key → {company, name, regex (nullable), signatures}. */
    private final Map<String, WafEntry> wafs;
    /** Signature string "checksum:base64" → list of WAF keys that own it. */
    private final Map<String, List<String>> signatureOwners;
    /** Compiled passive regexes (one per WAF that has one). */
    private final Map<String, Pattern> passivePatterns;

    private WafSignatures(List<String> payloadsRaw,
                          List<String> payloadValues,
                          List<String> payloadCategories,
                          int[] markers,
                          Map<String, WafEntry> wafs,
                          Map<String, List<String>> signatureOwners,
                          Map<String, Pattern> passivePatterns) {
        this.payloadsRaw = Collections.unmodifiableList(payloadsRaw);
        this.payloadValues = Collections.unmodifiableList(payloadValues);
        this.payloadCategories = Collections.unmodifiableList(payloadCategories);
        this.markers = markers;
        this.wafs = Collections.unmodifiableMap(wafs);
        this.signatureOwners = Collections.unmodifiableMap(signatureOwners);
        this.passivePatterns = Collections.unmodifiableMap(passivePatterns);
    }

    public static WafSignatures get() {
        WafSignatures local = instance;
        if (local != null) return local;
        synchronized (WafSignatures.class) {
            if (instance == null) {
                instance = load();
            }
            return instance;
        }
    }

    private static WafSignatures load() {
        try (InputStream in = WafSignatures.class.getResourceAsStream("/identywaf-data.json")) {
            if (in == null) {
                throw new IllegalStateException(
                        "identywaf-data.json resource not found on the classpath");
            }
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.UTF_8))) {
                char[] buf = new char[8192];
                int n;
                while ((n = r.read(buf)) > 0) sb.append(buf, 0, n);
            }
            return parse(JsonParser.parseString(sb.toString()).getAsJsonObject());
        } catch (IOException ex) {
            throw new IllegalStateException("failed to load identywaf-data.json", ex);
        }
    }

    private static WafSignatures parse(JsonObject root) {
        JsonArray payloadsArr = root.getAsJsonArray("payloads");
        List<String> payloadsRaw = new ArrayList<>(payloadsArr.size());
        List<String> payloadValues = new ArrayList<>(payloadsArr.size());
        List<String> payloadCategories = new ArrayList<>(payloadsArr.size());
        int[] markers = new int[payloadsArr.size()];
        for (int i = 0; i < payloadsArr.size(); i++) {
            String raw = payloadsArr.get(i).getAsString();
            int sep = raw.indexOf("::");
            String cat = sep < 0 ? "" : raw.substring(0, sep);
            String val = sep < 0 ? raw : raw.substring(sep + 2);
            payloadsRaw.add(raw);
            payloadCategories.add(cat);
            payloadValues.add(val);
            markers[i] = (crc16(val.getBytes(StandardCharsets.UTF_8)) << 1) & 0xffff;
        }

        JsonObject wafsObj = root.getAsJsonObject("wafs");
        Map<String, WafEntry> wafs = new LinkedHashMap<>();
        Map<String, List<String>> owners = new HashMap<>();
        Map<String, Pattern> passive = new LinkedHashMap<>();
        for (String key : wafsObj.keySet()) {
            JsonObject item = wafsObj.getAsJsonObject(key);
            String company = item.has("company") ? item.get("company").getAsString() : key;
            String name = item.has("name") ? item.get("name").getAsString() : key;
            String regex = item.has("regex") && !item.get("regex").isJsonNull()
                    ? item.get("regex").getAsString() : null;
            List<String> sigs = new ArrayList<>();
            if (item.has("signatures")) {
                for (var e : item.getAsJsonArray("signatures")) {
                    sigs.add(e.getAsString());
                }
            }
            wafs.put(key, new WafEntry(company, name, regex, Collections.unmodifiableList(sigs)));
            for (String s : sigs) {
                owners.computeIfAbsent(s, k -> new ArrayList<>()).add(key);
            }
            if (regex != null && !regex.isEmpty()) {
                try {
                    passive.put(key, compilePythonFlagRegex(regex));
                } catch (RuntimeException ex) {
                    // Skip WAFs whose regex Java's engine refuses — rare.
                }
            }
        }
        // Freeze inner lists.
        Map<String, List<String>> ownersFrozen = new HashMap<>();
        for (var e : owners.entrySet()) {
            ownersFrozen.put(e.getKey(), Collections.unmodifiableList(e.getValue()));
        }
        return new WafSignatures(payloadsRaw, payloadValues, payloadCategories,
                markers, wafs, ownersFrozen, passive);
    }

    // --- Public accessors -------------------------------------------------

    public int payloadCount()                   { return payloadValues.size(); }
    public String payloadValue(int i)           { return payloadValues.get(i); }
    public String payloadCategory(int i)        { return payloadCategories.get(i); }
    public List<String> payloadValues()         { return payloadValues; }
    public List<String> payloadCategories()     { return payloadCategories; }

    /** Pretty name — "{name}" or "{name} ({company})" when they differ. */
    public String displayName(String wafKey) {
        WafEntry w = wafs.get(wafKey);
        if (w == null) return wafKey;
        return w.name.equalsIgnoreCase(w.company)
                ? w.name
                : w.name + " (" + w.company + ")";
    }

    // --- Passive match ---------------------------------------------------

    /**
     * Tries every WAF regex in the catalog against {@code rawResponse}
     * (typically {@code status-line + headers + "\n\n" + body}). Returns
     * the display name of the first WAF that matches, or {@code null}.
     */
    public String matchPassive(String rawResponse) {
        if (rawResponse == null || rawResponse.isEmpty()) return null;
        for (var e : passivePatterns.entrySet()) {
            try {
                if (e.getValue().matcher(rawResponse).find()) {
                    return displayName(e.getKey());
                }
            } catch (RuntimeException ignored) {
                // Defensive: a pathological regex crash should not nuke detection.
            }
        }
        return null;
    }

    // --- Blind inference -------------------------------------------------

    /**
     * identYwaf's minimum blocked-payload count before partial matching
     * becomes meaningful. With fewer than this many positive hits the
     * partial-match arithmetic degenerates (most of the "match" comes from
     * markers that are NOT blocked in common, which coincidentally line up
     * for many WAFs), so identYwaf declines to report a partial-match at
     * all. We mirror that here.
     */
    private static final int MIN_MATCH_PARTIAL = 5;

    /**
     * identYwaf's blind match: build the "checksum:base64" signature from
     * the {@code blocked[]} vector (length must equal {@link #payloadCount()}),
     * look it up as an exact match first, then fall back to a partial
     * match that reports a percentage per WAF — skipped when fewer than
     * {@value #MIN_MATCH_PARTIAL} payloads were blocked (too few to
     * discriminate between WAFs).
     *
     * @return ordered map {display-name → confidence percent}, highest
     *         first. Exact matches report 100. Empty when no WAF has any
     *         marker in common with the observed vector or when the
     *         blocked-count is below the partial-match threshold.
     */
    public LinkedHashMap<String, Integer> matchBlind(boolean[] blocked) {
        if (blocked == null || blocked.length != payloadValues.size()) {
            throw new IllegalArgumentException(
                    "blocked[] length must equal payloadCount() = " + payloadValues.size());
        }
        String signature = computeSignature(blocked);
        LinkedHashMap<String, Integer> out = new LinkedHashMap<>();
        List<String> exact = signatureOwners.get(signature);
        if (exact != null) {
            for (String wafKey : exact) out.put(displayName(wafKey), 100);
            return out;
        }

        // Count how many payloads we observed as "blocked". Below the
        // identYwaf threshold, declining to partial-match avoids the
        // noise that plagues near-empty vectors (every signature scores
        // high by coincidence on the not-blocked markers).
        int blockedCount = 0;
        for (boolean b : blocked) if (b) blockedCount++;
        if (blockedCount < MIN_MATCH_PARTIAL) {
            return out;
        }

        // Partial: for every candidate signature in the catalog, count how
        // many markers appear in the observed set with the same blocked
        // bit (counter_y), vs how many markers appear with the opposite
        // bit (counter_n). Percent = y / (y + n). identYwaf uses this same
        // formula.
        // Build the set of observed uint16 markers (marker | blocked).
        java.util.Set<Integer> observed = new java.util.HashSet<>();
        for (int i = 0; i < blocked.length; i++) {
            int bit = blocked[i] ? 1 : 0;
            observed.add((markers[i] | bit) & 0xffff);
        }

        Map<String, Integer> matches = new HashMap<>();
        for (var ownerEntry : signatureOwners.entrySet()) {
            int y = 0, n = 0;
            byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(ownerEntry.getKey().split(":", 2)[1]);
            } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException ex) {
                continue;
            }
            if (decoded.length % 2 != 0) continue;
            for (int i = 0; i < decoded.length; i += 2) {
                int part = ((decoded[i] & 0xff) << 8) | (decoded[i + 1] & 0xff);
                if (observed.contains(part)) {
                    y++;
                } else if (observed.contains(part & ~1) || observed.contains(part | 1)) {
                    n++;
                }
            }
            if (y + n == 0) continue;
            int pct = (int) Math.round(100.0 * y / (y + n));
            for (String waf : ownerEntry.getValue()) {
                String display = displayName(waf);
                Integer prev = matches.get(display);
                if (prev == null || pct > prev) {
                    matches.put(display, pct);
                }
            }
        }
        matches.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .forEach(e -> out.put(e.getKey(), e.getValue()));
        return out;
    }

    /**
     * Build identYwaf's signature from a blocked-vector:
     * {@code hex(crc16(blob)):base64(blob)} where {@code blob} is
     * the big-endian concatenation of {@code (marker_i | blocked_i)} uint16s.
     */
    public String computeSignature(boolean[] blocked) {
        byte[] blob = new byte[blocked.length * 2];
        for (int i = 0; i < blocked.length; i++) {
            int v = (markers[i] | (blocked[i] ? 1 : 0)) & 0xffff;
            blob[2 * i]     = (byte) ((v >> 8) & 0xff);
            blob[2 * i + 1] = (byte) (v & 0xff);
        }
        int checksum = crc16(blob);
        String hex = String.format("%04x", checksum);
        return hex + ":" + Base64.getEncoder().encodeToString(blob);
    }

    // --- Helpers ---------------------------------------------------------

    /** identYwaf's {@code calc_hash}: low 16 bits of CRC-32 of {@code value}. */
    static int crc16(byte[] value) {
        CRC32 c = new CRC32();
        c.update(value);
        return (int) (c.getValue() & 0xffffL);
    }

    /**
     * identYwaf writes regexes with Python-style inline flag groups like
     * {@code (?i)...} or {@code (?is)...}. Python supports them anywhere
     * in the pattern; Java accepts them only at the very start and has a
     * narrower set. This helper strips every inline-flag group and ORs
     * them into {@code Pattern.compile} flags instead.
     */
    static Pattern compilePythonFlagRegex(String pattern) {
        int flags = 0;
        java.util.regex.Matcher m = Pattern
                .compile("\\(\\?([imsx]+)\\)")
                .matcher(pattern);
        StringBuilder stripped = new StringBuilder();
        int last = 0;
        while (m.find()) {
            stripped.append(pattern, last, m.start());
            for (char c : m.group(1).toCharArray()) {
                switch (c) {
                    case 'i': flags |= Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE; break;
                    case 'm': flags |= Pattern.MULTILINE; break;
                    case 's': flags |= Pattern.DOTALL; break;
                    case 'x': flags |= Pattern.COMMENTS; break;
                    default: break;
                }
            }
            last = m.end();
        }
        stripped.append(pattern.substring(last));
        return Pattern.compile(stripped.toString(), flags);
    }

    /** Immutable WAF record. */
    static final class WafEntry {
        final String company;
        final String name;
        final String regex;              // nullable
        final List<String> signatures;   // "checksum:base64" strings
        WafEntry(String company, String name, String regex, List<String> signatures) {
            this.company = company;
            this.name = name;
            this.regex = regex;
            this.signatures = signatures;
        }
    }

    // Convenience for diagnostics (not used in hot paths).
    @Override
    public String toString() {
        return "WafSignatures{wafs=" + wafs.size()
                + ", payloads=" + payloadValues.size()
                + ", passivePatterns=" + passivePatterns.size()
                + ", uniqueSignatures=" + signatureOwners.size() + "}";
    }

    /** For tests that need to assert WAF display names without triggering lookups. */
    public List<String> allWafDisplayNames() {
        return wafs.keySet().stream().map(this::displayName).collect(Collectors.toList());
    }

    public int wafCount() {
        return wafs.size();
    }
}
