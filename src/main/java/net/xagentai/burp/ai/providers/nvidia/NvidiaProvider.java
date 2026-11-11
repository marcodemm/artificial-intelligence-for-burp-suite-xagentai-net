package net.xagentai.burp.ai.providers.nvidia;

import burp.api.montoya.MontoyaApi;

import net.xagentai.burp.ai.config.ProviderKind;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.BaseOpenAICompatProvider;

/**
 * NVIDIA NIM / API Catalog provider — OpenAI-compatible endpoint hosted by
 * NVIDIA, with their own model catalog (Meta Llama, Mistral, Nemotron, ...).
 *
 * Endpoint:  POST {baseUrl}/v1/chat/completions
 * Headers:   Authorization: Bearer nvapi-{apiKey}
 * Default:   https://integrate.api.nvidia.com
 */
public final class NvidiaProvider extends BaseOpenAICompatProvider {

    public static final String ID = "nvidia";

    public NvidiaProvider(MontoyaApi api, XagentConfig config) {
        super(api, config);
    }

    @Override public String id() { return ID; }
    @Override public String displayName() { return "NVIDIA NIM"; }
    @Override public ProviderKind kind() { return ProviderKind.CLOUD; }

    @Override protected String baseUrl()   { return config.nvidiaBaseUrl(); }
    @Override protected String apiKey()    { return config.nvidiaApiKey(); }
    @Override protected String model()     { return config.nvidiaModel(); }
    @Override protected int maxTokens()    { return config.nvidiaMaxTokens(); }
    @Override protected double temperature() { return config.nvidiaTemperature(); }
    @Override protected int timeoutSeconds() { return config.nvidiaTimeoutSeconds(); }
    @Override protected String defaultModel() { return "meta/llama-3.3-70b-instruct"; }
}
