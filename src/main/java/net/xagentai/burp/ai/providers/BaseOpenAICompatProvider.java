package net.xagentai.burp.ai.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import net.xagentai.burp.ai.config.ProviderKind;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.util.HttpJson;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Base class for providers that speak the OpenAI Chat Completions API
 * (OpenAI, NVIDIA NIM, Ollama, llama.cpp, LM Studio-style).
 *
 * Subclasses only configure URL, API key, model and limits via the abstract
 * getters; everything else (POST, auth, body shape, parsing) is here.
 */
public abstract class BaseOpenAICompatProvider implements AIProvider {

    protected final MontoyaApi api;
    protected final Logging log;
    protected final XagentConfig config;

    protected BaseOpenAICompatProvider(MontoyaApi api, XagentConfig config) {
        this.api = api;
        this.log = api.logging();
        this.config = config;
    }

    // --- Subclass contract -------------------------------------------------

    protected abstract String baseUrl();
    protected abstract String apiKey();
    protected abstract String model();
    protected abstract int maxTokens();
    protected abstract double temperature();
    protected abstract int timeoutSeconds();
    protected abstract String defaultModel();

    /**
     * Path (appended to the normalized base URL) for the Chat Completions
     * endpoint. Defaults to the plain OpenAI spelling. Overridden by providers
     * that host the OpenAI-compat layer under a non-standard path, e.g.
     * Google Gemini at {@code /v1beta/openai/chat/completions}.
     */
    protected String chatEndpointPath() {
        return "/v1/chat/completions";
    }

    /**
     * Path (appended to the normalized base URL) for the Models list endpoint
     * used by {@link #autoDetectModel(String)}. Default is OpenAI spelling.
     */
    protected String modelsEndpointPath() {
        return "/v1/models";
    }

    /** Add auth header to the outgoing request. Default: Bearer token. Override as needed. */
    protected void addAuthHeader(Map<String, String> headers) {
        String key = apiKey();
        if (key != null && !key.isBlank()) {
            headers.put("Authorization", "Bearer " + key);
        }
    }

    /** Vendor-specific rule: does this model reject the "temperature" field? */
    protected boolean temperatureIsDeprecated(String modelId) {
        return false;
    }

    // --- AIProvider --------------------------------------------------------

    @Override
    public boolean isConfigured() {
        if (baseUrl() == null || baseUrl().isBlank()) return false;
        // Cloud providers need a key; local ones don't.
        if (kind() == ProviderKind.CLOUD) {
            return apiKey() != null && !apiKey().isBlank();
        }
        return true;
    }

    @Override
    public AIResponse send(AIRequest request) throws AIException {
        String base = normalizeBase(baseUrl());
        if (base.isEmpty()) {
            throw new AIException(displayName() + ": base URL is not configured.");
        }
        String url = base + chatEndpointPath();

        String modelId = model();
        if (modelId == null || modelId.isBlank()) {
            // Try auto-detect from /v1/models; fall back to the hardcoded default.
            try {
                modelId = autoDetectModel(base);
            } catch (Exception ignored) {
                modelId = null;
            }
            if (modelId == null || modelId.isBlank()) {
                modelId = defaultModel();
            }
        }
        if (modelId == null || modelId.isBlank()) {
            throw new AIException(displayName() + ": no model is configured and auto-detect failed.");
        }

        int mt = maxTokens() > 0 ? maxTokens() : 4096;

        JsonObject body = new JsonObject();
        body.addProperty("model", modelId);
        body.addProperty("max_tokens", mt);
        body.addProperty("stream", false);
        if (!temperatureIsDeprecated(modelId)) {
            body.addProperty("temperature", clamp(request.temperature(), 0.0, 2.0));
        }

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
        addAuthHeader(headers);

        try {
            String resp = HttpJson.post(api, url, headers, body.toString(), timeoutSeconds());
            return parseOpenAIChat(resp, modelId);
        } catch (IOException e) {
            throw new AIException(displayName() + " call failed: " + e.getMessage(), e);
        }
    }

    @Override
    public TestResult testConnection() {
        if (!isConfigured()) {
            return TestResult.fail(displayName() + " is not configured.");
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

    // --- Helpers -----------------------------------------------------------

    protected String autoDetectModel(String base) throws IOException {
        Map<String, String> h = new LinkedHashMap<>();
        addAuthHeader(h);
        String body = HttpJson.get(api, base + modelsEndpointPath(), h, 10);
        JsonObject root = JsonParser.parseString(body).getAsJsonObject();
        if (root.has("data") && root.get("data").isJsonArray()) {
            JsonArray data = root.getAsJsonArray("data");
            if (!data.isEmpty()) {
                return data.get(0).getAsJsonObject().get("id").getAsString();
            }
        }
        return null;
    }

    protected AIResponse parseOpenAIChat(String body, String fallbackModel) throws AIException {
        try {
            JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            String content = "";
            String fallbackSource = null;
            if (root.has("choices") && root.get("choices").isJsonArray()) {
                JsonArray choices = root.getAsJsonArray("choices");
                if (!choices.isEmpty()) {
                    JsonObject first = choices.get(0).getAsJsonObject();
                    if (first.has("message") && first.get("message").isJsonObject()) {
                        JsonObject m = first.getAsJsonObject("message");
                        if (m.has("content") && !m.get("content").isJsonNull()) {
                            content = m.get("content").getAsString();
                        }
                        // Reasoning-model fallback: NVIDIA Nemotron "super",
                        // some OpenAI o-series responses and other
                        // chain-of-thought models sometimes emit nothing in
                        // `content` and put the actual answer in
                        // `reasoning_content` or `reasoning`. Treat those as
                        // the real content when the standard field is empty.
                        if (content.isEmpty() && m.has("reasoning_content")
                                && !m.get("reasoning_content").isJsonNull()) {
                            content = m.get("reasoning_content").getAsString();
                            fallbackSource = "reasoning_content";
                        }
                        if (content.isEmpty() && m.has("reasoning")
                                && !m.get("reasoning").isJsonNull()
                                && m.get("reasoning").isJsonPrimitive()) {
                            content = m.get("reasoning").getAsString();
                            fallbackSource = "reasoning";
                        }
                        if (content.isEmpty()) {
                            // Log the shape so the operator can tell WHY it
                            // was empty (budget exhausted on reasoning, API
                            // returned a different envelope, etc.).
                            StringBuilder keys = new StringBuilder();
                            for (String k : m.keySet()) {
                                if (keys.length() > 0) keys.append(',');
                                keys.append(k);
                            }
                            log.logToOutput("[" + displayName() + "] empty content from provider — "
                                    + "message object keys were: [" + keys + "] · raw body length "
                                    + body.length() + " chars");
                        } else if (fallbackSource != null) {
                            log.logToOutput("[" + displayName() + "] message.content was empty; "
                                    + "falling back to message." + fallbackSource + " ("
                                    + content.length() + " chars)");
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
            throw new AIException("Failed to parse " + displayName() + " response: " + e.getMessage(), e);
        }
    }

    /**
     * Strip trailing slash(es) and a trailing {@code /v1} so the base URL can be
     * concatenated with {@link #chatEndpointPath()}. Overridable because
     * Gemini's documented base URL ends in {@code /v1beta/openai}, which must
     * also be stripped before we append {@code /v1beta/openai/chat/completions}.
     */
    protected String normalizeBase(String url) {
        if (url == null || url.isBlank()) return "";
        String s = url.trim();
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        if (s.endsWith("/v1")) s = s.substring(0, s.length() - 3);
        return s;
    }

    protected static double clamp(double t, double min, double max) {
        if (Double.isNaN(t)) return (min + max) / 2.0;
        return Math.max(min, Math.min(max, t));
    }
}
