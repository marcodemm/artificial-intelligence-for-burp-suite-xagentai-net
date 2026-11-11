package net.xagentai.burp.ai.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import com.google.gson.Gson;

/**
 * Loads and saves the extension configuration through Burp's PersistedObject
 * (extension-scoped preferences, persisted across Burp restarts).
 */
public final class ConfigStore {

    private static final String KEY = "xagentai.config.v1";

    private final MontoyaApi api;
    private final Gson gson = new Gson();

    public ConfigStore(MontoyaApi api) {
        this.api = api;
    }

    public XagentConfig load() {
        PersistedObject prefs = api.persistence().extensionData();
        String json = prefs.getString(KEY);
        if (json == null || json.isBlank()) {
            return new XagentConfig();
        }
        try {
            XagentConfig cfg = gson.fromJson(json, XagentConfig.class);
            return cfg == null ? new XagentConfig() : cfg;
        } catch (Exception e) {
            api.logging().logToError("Failed to parse XagentAI config, using defaults: " + e.getMessage());
            return new XagentConfig();
        }
    }

    public void save(XagentConfig config) {
        PersistedObject prefs = api.persistence().extensionData();
        prefs.setString(KEY, gson.toJson(config));
    }
}
