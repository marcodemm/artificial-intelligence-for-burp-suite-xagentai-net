package net.xagentai.burp.ai.config;

/** Whether an AI provider runs in the cloud or on the operator's machine. */
public enum ProviderKind {
    /** Cloud-hosted provider (Anthropic, OpenAI, Gemini, NVIDIA, ...). */
    CLOUD,
    /** Local provider (LM Studio, Ollama, llama.cpp). */
    LOCAL
}
