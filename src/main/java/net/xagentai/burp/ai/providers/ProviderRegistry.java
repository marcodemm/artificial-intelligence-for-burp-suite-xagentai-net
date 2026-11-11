package net.xagentai.burp.ai.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.claude.ClaudeProvider;
import net.xagentai.burp.ai.providers.llamacpp.LlamacppProvider;
import net.xagentai.burp.ai.providers.lmstudio.LMStudioProvider;
import net.xagentai.burp.ai.providers.nvidia.NvidiaProvider;
import net.xagentai.burp.ai.providers.ollama.OllamaProvider;
import net.xagentai.burp.ai.providers.openai.OpenAIProvider;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Keeps the set of registered AI providers and resolves the one marked
 * active in the current {@link XagentConfig}.
 */
public final class ProviderRegistry {

    private final XagentConfig config;
    private final Logging log;
    private final Map<String, AIProvider> providers = new LinkedHashMap<>();

    private ProviderRegistry(XagentConfig config, Logging log) {
        this.config = config;
        this.log = log;
    }

    public static ProviderRegistry withDefaults(MontoyaApi api, XagentConfig config) {
        ProviderRegistry r = new ProviderRegistry(config, api.logging());
        // Cloud providers
        r.register(new ClaudeProvider(api, config));
        r.register(new OpenAIProvider(api, config));
        r.register(new NvidiaProvider(api, config));
        // Local providers
        r.register(new LMStudioProvider(api, config));
        r.register(new OllamaProvider(api, config));
        r.register(new LlamacppProvider(api, config));
        return r;
    }

    public void register(AIProvider provider) {
        providers.put(provider.id(), provider);
    }

    /** Active provider, or the first registered one as fallback. */
    public AIProvider active() {
        AIProvider p = providers.get(config.activeProviderId());
        if (p != null) return p;
        return providers.values().iterator().next();
    }

    public AIProvider byId(String id) {
        return providers.get(id);
    }

    public Map<String, AIProvider> all() {
        return Collections.unmodifiableMap(providers);
    }
}
