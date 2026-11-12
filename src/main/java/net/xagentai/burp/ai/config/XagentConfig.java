package net.xagentai.burp.ai.config;

/**
 * Mutable configuration for the XagentAI extension.
 *
 * Serialized to / from JSON by {@link ConfigStore} via Gson (field-based).
 * Accessors follow record-style naming (no {@code get}/{@code set} prefix)
 * for readability.
 */
public final class XagentConfig {

    // --- Active provider --------------------------------------------------
    private String activeProviderId = "claude";

    // --- Claude (Anthropic) -----------------------------------------------
    private String claudeApiKey = "";
    private String claudeBaseUrl = "https://api.anthropic.com";
    private String claudeModel = "claude-haiku-5-5";
    private int claudeMaxTokens = 8192;
    private double claudeTemperature = 0.2d;
    private int claudeTimeoutSeconds = 60;

    // --- LM Studio (local) ------------------------------------------------
    private String lmStudioBaseUrl = "http://localhost:1234/v1";
    /** Empty = auto-detect via GET /v1/models and use the loaded model. */
    private String lmStudioModel = "";
    private int lmStudioMaxTokens = 8192;
    private double lmStudioTemperature = 0.2d;
    // 10 minutes — local models can be very slow at prompt processing +
    // generation, especially large reasoning variants like Bughunter-v10.
    private int lmStudioTimeoutSeconds = 600;

    // --- OpenAI (ChatGPT) -------------------------------------------------
    private String openaiApiKey = "";
    private String openaiBaseUrl = "https://api.openai.com";
    private String openaiModel = "gpt-4o-mini";
    private int openaiMaxTokens = 8192;
    private double openaiTemperature = 0.2d;
    private int openaiTimeoutSeconds = 90;

    // --- NVIDIA NIM / API Catalog ----------------------------------------
    private String nvidiaApiKey = "";
    private String nvidiaBaseUrl = "https://integrate.api.nvidia.com";
    private String nvidiaModel = "nvidia/nemotron-3.5-super-vl-120b-a12b";
    private int nvidiaMaxTokens = 8192;
    private double nvidiaTemperature = 0.2d;
    private int nvidiaTimeoutSeconds = 90;

    // --- Ollama (local) ---------------------------------------------------
    private String ollamaBaseUrl = "http://localhost:11434";
    /** Empty = auto-detect via GET /v1/models. */
    private String ollamaModel = "";
    private int ollamaMaxTokens = 8192;
    private double ollamaTemperature = 0.2d;
    private int ollamaTimeoutSeconds = 600;

    // --- llama.cpp (local, via llama-server) ------------------------------
    private String llamacppBaseUrl = "http://localhost:8080";
    private String llamacppModel = "";
    private int llamacppMaxTokens = 8192;
    private double llamacppTemperature = 0.2d;
    private int llamacppTimeoutSeconds = 600;

    // --- Behaviour --------------------------------------------------------
    private SanitizationMode sanitizationMode = SanitizationMode.AUTO;

    /** Optional override for the system prompt. Empty = use the built-in template. */
    private String systemPrompt = "";

    // --- Accessors (record-style) -----------------------------------------
    public String activeProviderId() { return activeProviderId; }
    public void activeProviderId(String v) { this.activeProviderId = v; }

    public String claudeApiKey() { return claudeApiKey; }
    public void claudeApiKey(String v) { this.claudeApiKey = v; }

    public String claudeBaseUrl() { return claudeBaseUrl; }
    public void claudeBaseUrl(String v) { this.claudeBaseUrl = v; }

    public String claudeModel() { return claudeModel; }
    public void claudeModel(String v) { this.claudeModel = v; }

    public int claudeMaxTokens() { return claudeMaxTokens; }
    public void claudeMaxTokens(int v) { this.claudeMaxTokens = v; }

    public double claudeTemperature() { return claudeTemperature; }
    public void claudeTemperature(double v) { this.claudeTemperature = v; }

    public int claudeTimeoutSeconds() { return claudeTimeoutSeconds; }
    public void claudeTimeoutSeconds(int v) { this.claudeTimeoutSeconds = v; }

    public String lmStudioBaseUrl() { return lmStudioBaseUrl; }
    public void lmStudioBaseUrl(String v) { this.lmStudioBaseUrl = v; }

    public String lmStudioModel() { return lmStudioModel; }
    public void lmStudioModel(String v) { this.lmStudioModel = v; }

    public int lmStudioMaxTokens() { return lmStudioMaxTokens; }
    public void lmStudioMaxTokens(int v) { this.lmStudioMaxTokens = v; }

    public double lmStudioTemperature() { return lmStudioTemperature; }
    public void lmStudioTemperature(double v) { this.lmStudioTemperature = v; }

    public int lmStudioTimeoutSeconds() { return lmStudioTimeoutSeconds; }
    public void lmStudioTimeoutSeconds(int v) { this.lmStudioTimeoutSeconds = v; }

    public String openaiApiKey() { return openaiApiKey; }
    public void openaiApiKey(String v) { this.openaiApiKey = v; }

    public String openaiBaseUrl() { return openaiBaseUrl; }
    public void openaiBaseUrl(String v) { this.openaiBaseUrl = v; }

    public String openaiModel() { return openaiModel; }
    public void openaiModel(String v) { this.openaiModel = v; }

    public int openaiMaxTokens() { return openaiMaxTokens; }
    public void openaiMaxTokens(int v) { this.openaiMaxTokens = v; }

    public double openaiTemperature() { return openaiTemperature; }
    public void openaiTemperature(double v) { this.openaiTemperature = v; }

    public int openaiTimeoutSeconds() { return openaiTimeoutSeconds; }
    public void openaiTimeoutSeconds(int v) { this.openaiTimeoutSeconds = v; }

    public String nvidiaApiKey() { return nvidiaApiKey; }
    public void nvidiaApiKey(String v) { this.nvidiaApiKey = v; }

    public String nvidiaBaseUrl() { return nvidiaBaseUrl; }
    public void nvidiaBaseUrl(String v) { this.nvidiaBaseUrl = v; }

    public String nvidiaModel() { return nvidiaModel; }
    public void nvidiaModel(String v) { this.nvidiaModel = v; }

    public int nvidiaMaxTokens() { return nvidiaMaxTokens; }
    public void nvidiaMaxTokens(int v) { this.nvidiaMaxTokens = v; }

    public double nvidiaTemperature() { return nvidiaTemperature; }
    public void nvidiaTemperature(double v) { this.nvidiaTemperature = v; }

    public int nvidiaTimeoutSeconds() { return nvidiaTimeoutSeconds; }
    public void nvidiaTimeoutSeconds(int v) { this.nvidiaTimeoutSeconds = v; }

    public String ollamaBaseUrl() { return ollamaBaseUrl; }
    public void ollamaBaseUrl(String v) { this.ollamaBaseUrl = v; }

    public String ollamaModel() { return ollamaModel; }
    public void ollamaModel(String v) { this.ollamaModel = v; }

    public int ollamaMaxTokens() { return ollamaMaxTokens; }
    public void ollamaMaxTokens(int v) { this.ollamaMaxTokens = v; }

    public double ollamaTemperature() { return ollamaTemperature; }
    public void ollamaTemperature(double v) { this.ollamaTemperature = v; }

    public int ollamaTimeoutSeconds() { return ollamaTimeoutSeconds; }
    public void ollamaTimeoutSeconds(int v) { this.ollamaTimeoutSeconds = v; }

    public String llamacppBaseUrl() { return llamacppBaseUrl; }
    public void llamacppBaseUrl(String v) { this.llamacppBaseUrl = v; }

    public String llamacppModel() { return llamacppModel; }
    public void llamacppModel(String v) { this.llamacppModel = v; }

    public int llamacppMaxTokens() { return llamacppMaxTokens; }
    public void llamacppMaxTokens(int v) { this.llamacppMaxTokens = v; }

    public double llamacppTemperature() { return llamacppTemperature; }
    public void llamacppTemperature(double v) { this.llamacppTemperature = v; }

    public int llamacppTimeoutSeconds() { return llamacppTimeoutSeconds; }
    public void llamacppTimeoutSeconds(int v) { this.llamacppTimeoutSeconds = v; }

    public SanitizationMode sanitizationMode() {
        return sanitizationMode == null ? SanitizationMode.defaultMode() : sanitizationMode;
    }
    public void sanitizationMode(SanitizationMode v) {
        this.sanitizationMode = v == null ? SanitizationMode.defaultMode() : v;
    }

    public String systemPrompt() { return systemPrompt; }
    public void systemPrompt(String v) { this.systemPrompt = v; }
}
