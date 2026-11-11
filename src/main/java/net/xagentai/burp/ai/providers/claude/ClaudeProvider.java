package net.xagentai.burp.ai.providers.claude;

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
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Anthropic Claude provider — uses the Messages API.
 *
 *   Endpoint:  POST {baseUrl}/v1/messages
 *   Headers:   x-api-key, anthropic-version: 2023-06-01, content-type: application/json
 *   Body:      { model, system, messages:[{role:'user', content:...}], max_tokens, temperature }
 *   Response:  { content:[{type:'text', text:...}], usage:{input_tokens, output_tokens}, model }
 */
public final class ClaudeProvider implements AIProvider {

    public static final String ID = "claude";

    private final MontoyaApi api;
    private final Logging log;
    private final XagentConfig config;

    public ClaudeProvider(MontoyaApi api, XagentConfig config) {
        this.api = api;
        this.log = api.logging();
        this.config = config;
    }

    @Override public String id() { return ID; }
    @Override public String displayName() { return "Claude (Anthropic)"; }
    @Override public ProviderKind kind() { return ProviderKind.CLOUD; }

    @Override
    public boolean isConfigured() {
        String key = config.claudeApiKey();
        return key != null && !key.isBlank();
    }

    @Override
    public AIResponse send(AIRequest request) throws AIException {
        String key = config.claudeApiKey();
        if (key == null || key.isBlank()) {
            throw new AIException("Claude API key is not configured. Set it in Settings → Claude.");
        }

        String base = normalizeBase(config.claudeBaseUrl());
        String url = base + "/v1/messages";

        String model = config.claudeModel();
        if (model == null || model.isBlank()) model = "claude-haiku-5-5";

        int maxTokens = request.maxTokens() > 0 ? request.maxTokens() : config.claudeMaxTokens();
        if (maxTokens <= 0) maxTokens = 4096;

        // Build JSON body.
        JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.addProperty("max_tokens", maxTokens);
        // Claude 5+ deprecated the `temperature` parameter; send it only for older models.
        if (!isClaudeV5OrLater(model)) {
            body.addProperty("temperature", clampTemperature(request.temperature()));
        }
        if (request.systemPrompt() != null && !request.systemPrompt().isBlank()) {
            body.addProperty("system", request.systemPrompt());
        }
        JsonArray messages = new JsonArray();
        JsonObject userMsg = new JsonObject();
        userMsg.addProperty("role", "user");
        userMsg.addProperty("content", request.userMessage() == null ? "" : request.userMessage());
        messages.add(userMsg);
        body.add("messages", messages);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("x-api-key", key);
        headers.put("anthropic-version", "2023-06-01");
        headers.put("Content-Type", "application/json");

        try {
            String responseBody = HttpJson.post(url, headers, body.toString(), config.claudeTimeoutSeconds());
            return parseResponse(responseBody, model);
        } catch (IOException e) {
            throw new AIException("Claude API call failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AIException("Claude API call interrupted", e);
        }
    }

    @Override
    public TestResult testConnection() {
        if (!isConfigured()) {
            return TestResult.fail("No API key configured");
        }
        try {
            long start = System.nanoTime();
            AIResponse r = send(new AIRequest("", "Reply with the single word: pong.", 10, 0.0d));
            long ms = (System.nanoTime() - start) / 1_000_000L;
            String snippet = r.content() == null ? "" : r.content();
            if (snippet.length() > 60) snippet = snippet.substring(0, 60) + "...";
            return TestResult.ok("reply: " + snippet.replace('\n', ' ').trim()
                    + " · in=" + r.inputTokens() + " out=" + r.outputTokens(), ms);
        } catch (AIException e) {
            return TestResult.fail(e.getMessage());
        }
    }

    private AIResponse parseResponse(String body, String fallbackModel) throws AIException {
        try {
            JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            StringBuilder text = new StringBuilder();
            if (root.has("content") && root.get("content").isJsonArray()) {
                for (JsonElement el : root.getAsJsonArray("content")) {
                    JsonObject o = el.getAsJsonObject();
                    String type = o.has("type") ? o.get("type").getAsString() : "";
                    if ("text".equals(type) && o.has("text")) {
                        text.append(o.get("text").getAsString());
                    }
                }
            }
            int inTok = 0, outTok = 0;
            if (root.has("usage") && root.get("usage").isJsonObject()) {
                JsonObject u = root.getAsJsonObject("usage");
                if (u.has("input_tokens"))  inTok  = u.get("input_tokens").getAsInt();
                if (u.has("output_tokens")) outTok = u.get("output_tokens").getAsInt();
            }
            String modelId = root.has("model") ? root.get("model").getAsString() : fallbackModel;
            return new AIResponse(text.toString(), inTok, outTok, modelId);
        } catch (Exception e) {
            throw new AIException("Failed to parse Claude response: " + e.getMessage(), e);
        }
    }

    private static String normalizeBase(String url) {
        if (url == null || url.isBlank()) return "https://api.anthropic.com";
        String s = url.trim();
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
    }

    private static double clampTemperature(double t) {
        if (Double.isNaN(t) || t < 0.0d) return 0.0d;
        if (t > 1.0d) return 1.0d; // Anthropic range is 0-1
        return t;
    }

    /**
     * Claude 5+ deprecated the {@code temperature} parameter — the API returns
     * HTTP 400 {@code "temperature is deprecated for this model"} if we send it.
     * Matches {@code claude-{opus|sonnet|haiku|fable}-{5..9}...}; older families
     * (Claude 3/4) still accept temperature.
     */
    static boolean isClaudeV5OrLater(String model) {
        if (model == null) return false;
        return model.matches("(?i)^claude-(opus|sonnet|haiku|fable)-[5-9].*");
    }
}
