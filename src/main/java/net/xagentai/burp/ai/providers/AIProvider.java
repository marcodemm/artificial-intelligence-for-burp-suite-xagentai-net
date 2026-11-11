package net.xagentai.burp.ai.providers;

import net.xagentai.burp.ai.config.ProviderKind;

/**
 * An AI backend the plugin can talk to.
 *
 * Implementations must be thread-safe: Burp may invoke the plugin from
 * multiple threads (context-menu handlers, Scanner threads, etc.).
 */
public interface AIProvider {

    /** Stable short id used in the config and in UI combos. */
    String id();

    /** Human-readable label for Settings UI and logs. */
    String displayName();

    /** Cloud vs local — drives sanitization decisions when mode is AUTO. */
    ProviderKind kind();

    /** True when the provider has the minimum config it needs to operate. */
    boolean isConfigured();

    /** Perform a single-turn completion. */
    AIResponse send(AIRequest request) throws AIException;

    /** Lightweight end-to-end check used by the Settings "Test" button. */
    TestResult testConnection();
}
