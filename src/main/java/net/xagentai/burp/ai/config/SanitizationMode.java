package net.xagentai.burp.ai.config;

/**
 * How the plugin should redact sensitive headers before sending a Burp
 * request/response to the AI provider.
 */
public enum SanitizationMode {

    /** Never redact. The operator takes full responsibility. */
    INACTIVE,

    /** Always redact sensitive headers, regardless of provider. */
    ACTIVE,

    /** Redact only when the active provider is cloud-hosted. Default. */
    AUTO;

    public static SanitizationMode defaultMode() {
        return AUTO;
    }
}
