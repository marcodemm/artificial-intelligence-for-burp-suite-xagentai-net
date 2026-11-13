package net.xagentai.burp.ai.providers.gemini;

import burp.api.montoya.MontoyaApi;

import net.xagentai.burp.ai.config.ProviderKind;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.BaseOpenAICompatProvider;

/**
 * Google Gemini provider — uses Google's OpenAI-compatible endpoint hosted at
 * {@code https://generativelanguage.googleapis.com/v1beta/openai/}.
 *
 * <pre>
 * Endpoint:  POST {baseUrl}/v1beta/openai/chat/completions
 * Headers:   Authorization: Bearer {GEMINI_API_KEY}
 * Body:      Standard OpenAI chat-completions shape (messages, model, ...)
 * Response:  Standard OpenAI chat-completions shape (choices[0].message.content)
 * </pre>
 *
 * Reference: Google AI Studio → "OpenAI libraries" docs
 * (the OpenAI-compat layer is in beta; feature support is a subset of the
 * native Gemini API).
 */
public final class GeminiProvider extends BaseOpenAICompatProvider {

    public static final String ID = "gemini";

    public GeminiProvider(MontoyaApi api, XagentConfig config) {
        super(api, config);
    }

    @Override public String id() { return ID; }
    @Override public String displayName() { return "Google Gemini"; }
    @Override public ProviderKind kind() { return ProviderKind.CLOUD; }

    @Override protected String baseUrl()         { return config.geminiBaseUrl(); }
    @Override protected String apiKey()          { return config.geminiApiKey(); }
    @Override protected String model()           { return config.geminiModel(); }
    @Override protected int maxTokens()          { return config.geminiMaxTokens(); }
    @Override protected double temperature()     { return config.geminiTemperature(); }
    @Override protected int timeoutSeconds()     { return config.geminiTimeoutSeconds(); }
    @Override protected String defaultModel()    { return "gemini-2.5-flash"; }

    /** Google hosts the OpenAI-compat layer under {@code /v1beta/openai/}. */
    @Override protected String chatEndpointPath()   { return "/v1beta/openai/chat/completions"; }
    @Override protected String modelsEndpointPath() { return "/v1beta/openai/models"; }

    /**
     * Also strip a trailing {@code /v1beta/openai} so an operator who pastes
     * Google's documented base URL verbatim still gets a correct final URL
     * (we re-append the full path via {@link #chatEndpointPath()}).
     */
    @Override
    protected String normalizeBase(String url) {
        String s = super.normalizeBase(url);
        if (s.endsWith("/v1beta/openai")) {
            s = s.substring(0, s.length() - "/v1beta/openai".length());
        } else if (s.endsWith("/v1beta")) {
            s = s.substring(0, s.length() - "/v1beta".length());
        }
        return s;
    }
}
