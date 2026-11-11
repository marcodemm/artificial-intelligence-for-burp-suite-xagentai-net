package net.xagentai.burp.ai.providers.openai;

import burp.api.montoya.MontoyaApi;

import net.xagentai.burp.ai.config.ProviderKind;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.BaseOpenAICompatProvider;

/**
 * OpenAI (ChatGPT) provider — uses the standard Chat Completions API.
 *
 * Endpoint:  POST {baseUrl}/v1/chat/completions
 * Headers:   Authorization: Bearer {apiKey}
 */
public final class OpenAIProvider extends BaseOpenAICompatProvider {

    public static final String ID = "openai";

    public OpenAIProvider(MontoyaApi api, XagentConfig config) {
        super(api, config);
    }

    @Override public String id() { return ID; }
    @Override public String displayName() { return "OpenAI (ChatGPT)"; }
    @Override public ProviderKind kind() { return ProviderKind.CLOUD; }

    @Override protected String baseUrl()   { return config.openaiBaseUrl(); }
    @Override protected String apiKey()    { return config.openaiApiKey(); }
    @Override protected String model()     { return config.openaiModel(); }
    @Override protected int maxTokens()    { return config.openaiMaxTokens(); }
    @Override protected double temperature() { return config.openaiTemperature(); }
    @Override protected int timeoutSeconds() { return config.openaiTimeoutSeconds(); }
    @Override protected String defaultModel() { return "gpt-4o-mini"; }

    /** GPT-5 and o1/o3 reasoning models deprecated the `temperature` parameter. */
    @Override
    protected boolean temperatureIsDeprecated(String m) {
        if (m == null) return false;
        return m.startsWith("gpt-5") || m.startsWith("o1") || m.startsWith("o3") || m.startsWith("o4");
    }
}
