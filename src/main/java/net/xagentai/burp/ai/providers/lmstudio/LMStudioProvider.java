package net.xagentai.burp.ai.providers.lmstudio;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import net.xagentai.burp.ai.config.ProviderKind;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.AIException;
import net.xagentai.burp.ai.providers.AIProvider;
import net.xagentai.burp.ai.providers.AIRequest;
import net.xagentai.burp.ai.providers.AIResponse;
import net.xagentai.burp.ai.providers.TestResult;
import net.xagentai.burp.ai.util.HttpJson;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * LM Studio local provider — OpenAI-compatible server.
 *
 * TODO v0.1: implement {@link #send(AIRequest)} and {@link #testConnection()}.
 *   Model resolution: if {@code config.lmStudioModel()} is blank, GET {baseUrl}/models
 *   and use the first entry (the currently loaded model in LM Studio).
 *   Endpoint:  POST {baseUrl}/chat/completions
 *   Body:      { model, messages:[{role:'system',content:...},{role:'user',content:...}],
 *                max_tokens, temperature }
 *   Response:  { choices:[{message:{content:...}}], usage:{prompt_tokens, completion_tokens}, model }
 */
public final class LMStudioProvider implements AIProvider {

    public static final String ID = "lmstudio";

    private final MontoyaApi api;
    private final Logging log;
    private final XagentConfig config;

    public LMStudioProvider(MontoyaApi api, XagentConfig config) {
        this.api = api;
        this.log = api.logging();
        this.config = config;
    }

    @Override public String id() { return ID; }
    @Override public String displayName() { return "LM Studio (local)"; }
    @Override public ProviderKind kind() { return ProviderKind.LOCAL; }

    @Override
    public boolean isConfigured() {
        String url = config.lmStudioBaseUrl();
        return url != null && !url.isBlank();
    }

    @Override
    public AIResponse send(AIRequest request) throws AIException {
        String host = normalizeBase(config.lmStudioBaseUrl());
        String url = host + "/v1/chat/completions";

        // Resolve model: use configured value, or auto-detect the loaded one.
        String model = config.lmStudioModel();
        if (model == null || model.isBlank()) {
            try {
                List<ModelInfo> models = listAvailableModels();
                model = models.stream().filter(ModelInfo::loaded).findFirst()
                        .or(() -> models.stream().findFirst())
                        .map(ModelInfo::id)
                        .orElseThrow(() -> new AIException("No models available in LM Studio at " + host));
            } catch (AIException e) {
                throw e;
            } catch (Exception e) {
                throw new AIException("Failed to auto-detect model from LM Studio: " + e.getMessage(), e);
            }
        }

        int maxTokens = request.maxTokens() > 0 ? request.maxTokens() : config.lmStudioMaxTokens();
        if (maxTokens <= 0) maxTokens = 4096;

        // OpenAI-compatible chat body.
        JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.addProperty("max_tokens", maxTokens);
        body.addProperty("temperature", clampTemperature(request.temperature()));
        body.addProperty("stream", false);

        JsonArray messages = new JsonArray();
        if (request.systemPrompt() != null && !request.systemPrompt().isBlank()) {
            JsonObject s = new JsonObject();
            s.addProperty("role", "system");
            s.addProperty("content", request.systemPrompt());
            messages.add(s);
        }
        JsonObject u = new JsonObject();
        u.addProperty("role", "user");
        u.addProperty("content", request.userMessage() == null ? "" : request.userMessage());
        messages.add(u);
        body.add("messages", messages);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");

        try {
            String resp = HttpJson.post(api, url, headers, body.toString(), config.lmStudioTimeoutSeconds());
            return parseOpenAIChat(resp, model);
        } catch (IOException e) {
            throw new AIException("LM Studio call failed: " + e.getMessage(), e);
        }
    }

    private AIResponse parseOpenAIChat(String body, String fallbackModel) throws AIException {
        try {
            JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            String content = "";
            if (root.has("choices") && root.get("choices").isJsonArray()) {
                JsonArray choices = root.getAsJsonArray("choices");
                if (!choices.isEmpty()) {
                    JsonObject first = choices.get(0).getAsJsonObject();
                    if (first.has("message") && first.get("message").isJsonObject()) {
                        JsonObject m = first.getAsJsonObject("message");
                        if (m.has("content") && !m.get("content").isJsonNull()) {
                            content = m.get("content").getAsString();
                        }
                    }
                }
            }
            int inTok = 0, outTok = 0;
            if (root.has("usage") && root.get("usage").isJsonObject()) {
                JsonObject usage = root.getAsJsonObject("usage");
                if (usage.has("prompt_tokens"))     inTok  = usage.get("prompt_tokens").getAsInt();
                if (usage.has("completion_tokens")) outTok = usage.get("completion_tokens").getAsInt();
            }
            String modelId = root.has("model") ? root.get("model").getAsString() : fallbackModel;
            return new AIResponse(content, inTok, outTok, modelId);
        } catch (Exception e) {
            throw new AIException("Failed to parse LM Studio response: " + e.getMessage(), e);
        }
    }

    private static double clampTemperature(double t) {
        if (Double.isNaN(t) || t < 0.0d) return 0.0d;
        if (t > 2.0d) return 2.0d;
        return t;
    }

    @Override
    public TestResult testConnection() {
        // Fetching /models is a cheap end-to-end check and reports which model (if any) is loaded.
        try {
            long start = System.nanoTime();
            List<ModelInfo> models = listAvailableModels();
            long ms = (System.nanoTime() - start) / 1_000_000L;
            String loaded = models.stream().filter(ModelInfo::loaded).findFirst().map(ModelInfo::id).orElse(null);
            String msg = models.size() + " model(s)" + (loaded != null ? " · loaded: " + loaded : " · none loaded");
            return TestResult.ok(msg, ms);
        } catch (Exception e) {
            return TestResult.fail(e.getMessage());
        }
    }

    /**
     * List models visible to LM Studio. Tries the extended {@code /api/v0/models}
     * endpoint first (reports {@code state: "loaded"} for the active model), and
     * falls back to the OpenAI-compatible {@code /v1/models} if that is unavailable.
     */
    public List<ModelInfo> listAvailableModels() throws IOException {
        String host = normalizeBase(config.lmStudioBaseUrl());
        try {
            List<ModelInfo> ext = fetchExtended(host);
            if (!ext.isEmpty()) return ext;
        } catch (Exception ignored) {
            // Fall through to the OpenAI-compat endpoint.
        }
        return fetchOpenAI(host);
    }

    private List<ModelInfo> fetchExtended(String host) throws IOException {
        String body = HttpJson.get(api, host + "/api/v0/models", null, 10);
        JsonObject root = JsonParser.parseString(body).getAsJsonObject();
        JsonArray data = root.getAsJsonArray("data");
        List<ModelInfo> out = new ArrayList<>();
        for (JsonElement e : data) {
            JsonObject o = e.getAsJsonObject();
            String id = o.get("id").getAsString();
            String state = (o.has("state") && !o.get("state").isJsonNull())
                    ? o.get("state").getAsString() : null;
            out.add(new ModelInfo(id, "loaded".equalsIgnoreCase(state)));
        }
        return out;
    }

    private List<ModelInfo> fetchOpenAI(String host) throws IOException {
        String body = HttpJson.get(api, host + "/v1/models", null, 10);
        JsonObject root = JsonParser.parseString(body).getAsJsonObject();
        JsonArray data = root.getAsJsonArray("data");
        List<ModelInfo> out = new ArrayList<>();
        for (JsonElement e : data) {
            out.add(new ModelInfo(e.getAsJsonObject().get("id").getAsString(), false));
        }
        return out;
    }

    /** Normalize an input base URL: strip trailing slash and drop the /v1 suffix if present. */
    private static String normalizeBase(String url) {
        if (url == null || url.isBlank()) return "http://localhost:1234";
        String s = url.trim();
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        if (s.endsWith("/v1")) s = s.substring(0, s.length() - 3);
        return s;
    }

    /** One model entry returned by LM Studio. {@code loaded} is true only via the extended API. */
    public record ModelInfo(String id, boolean loaded) {}
}
