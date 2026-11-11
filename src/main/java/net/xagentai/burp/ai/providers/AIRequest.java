package net.xagentai.burp.ai.providers;

/** A single-turn AI request. Multi-turn comes in v0.2. */
public record AIRequest(
        String systemPrompt,
        String userMessage,
        int maxTokens,
        double temperature
) {
}
