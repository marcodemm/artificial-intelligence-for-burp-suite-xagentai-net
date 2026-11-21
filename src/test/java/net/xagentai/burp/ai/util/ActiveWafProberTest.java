package net.xagentai.burp.ai.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the small bits of {@link ActiveWafProber} that we can
 * exercise without a live Burp runtime (the full probe needs
 * {@code api.http().sendRequest()} which only works in-extension).
 */
final class ActiveWafProberTest {

    @Test
    void explicitBlockStatusAccepts403_406_429_451_503() {
        assertTrue(ActiveWafProber.isExplicitBlockStatus(403));
        assertTrue(ActiveWafProber.isExplicitBlockStatus(406));
        assertTrue(ActiveWafProber.isExplicitBlockStatus(429));
        assertTrue(ActiveWafProber.isExplicitBlockStatus(451));
        assertTrue(ActiveWafProber.isExplicitBlockStatus(503));
    }

    @Test
    void explicitBlockStatusRejectsGenericErrorsAnd2xx() {
        // 400 is NOT counted as a block — generic app rejection.
        assertFalse(ActiveWafProber.isExplicitBlockStatus(400));
        // 401/404/500 are not WAF signals either (auth/ missing/ bug).
        assertFalse(ActiveWafProber.isExplicitBlockStatus(401));
        assertFalse(ActiveWafProber.isExplicitBlockStatus(404));
        assertFalse(ActiveWafProber.isExplicitBlockStatus(500));
        assertFalse(ActiveWafProber.isExplicitBlockStatus(200));
        assertFalse(ActiveWafProber.isExplicitBlockStatus(302));
    }

    @Test
    void catalogCategoriesContainsExpectedBuckets() {
        var cats = ActiveWafProber.catalogCategories();
        // identYwaf schema v1 ships at least these categories.
        assertTrue(cats.contains("SQLi"));
        assertTrue(cats.contains("XSS"));
        assertTrue(cats.contains("XXE"));
        assertTrue(cats.contains("LDAPi"));
        assertTrue(cats.contains("NOSQLi"));
        assertTrue(cats.contains("PT"), "path traversal category expected, got " + cats);
    }

    @Test
    void categorySummaryHandlesEmptyDetails() {
        String s = ActiveWafProber.categorySummary(java.util.Collections.emptyList());
        assertTrue(s.equals("none"), "expected 'none', got: " + s);
    }
}
