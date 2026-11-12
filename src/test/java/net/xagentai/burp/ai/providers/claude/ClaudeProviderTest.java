package net.xagentai.burp.ai.providers.claude;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClaudeProviderTest {

    @Test
    void detectsClaudeV5Family() {
        assertTrue(ClaudeProvider.isClaudeV5OrLater("claude-haiku-5-5"));
        assertTrue(ClaudeProvider.isClaudeV5OrLater("claude-sonnet-5-5"));
        assertTrue(ClaudeProvider.isClaudeV5OrLater("claude-opus-5-5"));
        assertTrue(ClaudeProvider.isClaudeV5OrLater("claude-fable-5-2"));
    }

    @Test
    void detectsFutureFamiliesUpToClaude9() {
        assertTrue(ClaudeProvider.isClaudeV5OrLater("claude-opus-6-0"));
        assertTrue(ClaudeProvider.isClaudeV5OrLater("claude-sonnet-9-9"));
    }

    @Test
    void isCaseInsensitive() {
        assertTrue(ClaudeProvider.isClaudeV5OrLater("Claude-Haiku-5-5"));
        assertTrue(ClaudeProvider.isClaudeV5OrLater("CLAUDE-OPUS-5-5"));
    }

    @Test
    void rejectsClaude3And4Families() {
        // Pre-5 models still accept the temperature parameter.
        assertFalse(ClaudeProvider.isClaudeV5OrLater("claude-3-5-haiku-20241022"));
        assertFalse(ClaudeProvider.isClaudeV5OrLater("claude-3-5-sonnet-20240620"));
        assertFalse(ClaudeProvider.isClaudeV5OrLater("claude-3-opus-20240229"));
        assertFalse(ClaudeProvider.isClaudeV5OrLater("claude-4-sonnet-20250101"));
    }

    @Test
    void rejectsUnrelatedStrings() {
        assertFalse(ClaudeProvider.isClaudeV5OrLater(""));
        assertFalse(ClaudeProvider.isClaudeV5OrLater(null));
        assertFalse(ClaudeProvider.isClaudeV5OrLater("gpt-5-mini"));
        assertFalse(ClaudeProvider.isClaudeV5OrLater("llama-3.3-70b"));
        assertFalse(ClaudeProvider.isClaudeV5OrLater("claude"));
        assertFalse(ClaudeProvider.isClaudeV5OrLater("not-claude-opus-5-5"),
                "Must only match strings that START with 'claude-'");
    }
}
