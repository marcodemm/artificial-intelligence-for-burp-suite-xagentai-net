package net.xagentai.burp.ai.providers.llamacpp;

import burp.api.montoya.MontoyaApi;

import net.xagentai.burp.ai.config.ProviderKind;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.BaseOpenAICompatProvider;

import java.util.Map;

/**
 * llama.cpp local provider — the {@code llama-server} binary exposes an
 * OpenAI-compatible endpoint at {@code /v1/chat/completions}.
 *
 * Endpoint:  POST {baseUrl}/v1/chat/completions
 * Auth:      none (local)
 * Default:   http://localhost:8080
 */
public final class LlamacppProvider extends BaseOpenAICompatProvider {

    public static final String ID = "llamacpp";

    public LlamacppProvider(MontoyaApi api, XagentConfig config) {
        super(api, config);
    }

    @Override public String id() { return ID; }
    @Override public String displayName() { return "llama.cpp (local)"; }
    @Override public ProviderKind kind() { return ProviderKind.LOCAL; }

    @Override protected String baseUrl()   { return config.llamacppBaseUrl(); }
    @Override protected String apiKey()    { return ""; }
    @Override protected String model()     { return config.llamacppModel(); }
    @Override protected int maxTokens()    { return config.llamacppMaxTokens(); }
    @Override protected double temperature() { return config.llamacppTemperature(); }
    @Override protected int timeoutSeconds() { return config.llamacppTimeoutSeconds(); }
    @Override protected String defaultModel() { return ""; }

    /** llama.cpp local server does not require an Authorization header. */
    @Override
    protected void addAuthHeader(Map<String, String> headers) {
        // intentionally empty
    }
}
