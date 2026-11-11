package net.xagentai.burp.ai.providers;

/** Normalized completion response across providers. */
public record AIResponse(
        String content,
        int inputTokens,
        int outputTokens,
        String modelId
) {
}
