package net.xagentai.burp.ai.providers.ollama;

import burp.api.montoya.MontoyaApi;

import net.xagentai.burp.ai.config.ProviderKind;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.BaseOpenAICompatProvider;

import java.util.Map;

/**
 * Ollama local provider — uses the OpenAI-compatible endpoint Ollama exposes
 * at {@code /v1/chat/completions} since version 0.1.x.
 *
 * Endpoint:  POST {baseUrl}/v1/chat/completions
 * Auth:      none (local)
 * Default:   http://localhost:11434
 */
public final class OllamaProvider extends BaseOpenAICompatProvider {

    public static final String ID = "ollama";

    public OllamaProvider(MontoyaApi api, XagentConfig config) {
        super(api, config);
    }

    @Override public String id() { return ID; }
    @Override public String displayName() { return "Ollama (local)"; }
    @Override public ProviderKind kind() { return ProviderKind.LOCAL; }

    @Override protected String baseUrl()   { return config.ollamaBaseUrl(); }
    @Override protected String apiKey()    { return ""; } // local, no auth
    @Override protected String model()     { return config.ollamaModel(); }
    @Override protected int maxTokens()    { return config.ollamaMaxTokens(); }
    @Override protected double temperature() { return config.ollamaTemperature(); }
    @Override protected int timeoutSeconds() { return config.ollamaTimeoutSeconds(); }
    @Override protected String defaultModel() { return ""; }

    /** Ollama does not want an Authorization header. */
    @Override
    protected void addAuthHeader(Map<String, String> headers) {
        // intentionally empty
    }
}
