package net.xagentai.burp.ai.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import net.xagentai.burp.ai.ExtensionLifecycle;
import net.xagentai.burp.ai.config.ConfigStore;
import net.xagentai.burp.ai.config.SanitizationMode;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.AIProvider;
import net.xagentai.burp.ai.providers.ProviderRegistry;
import net.xagentai.burp.ai.providers.TestResult;

import net.xagentai.burp.ai.providers.lmstudio.LMStudioProvider;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;

/**
 * Top-bar tab registered in Burp as "XagentAI". Edits the live {@link XagentConfig}
 * and persists via {@link ConfigStore}.
 */
public final class ConfigPanel extends JPanel {

    private final MontoyaApi api;
    private final Logging log;
    private final XagentConfig config;
    private final ConfigStore store;
    private final ProviderRegistry providers;

    // --- active provider ---
    private JComboBox<String> activeProviderCombo;

    // --- Claude ---
    private JPasswordField claudeApiKeyField;
    private JTextField claudeBaseUrlField;
    private JComboBox<String> claudeModelCombo;
    private JSpinner claudeMaxTokensSpinner;
    private JSpinner claudeTemperatureSpinner;
    private JSpinner claudeTimeoutSpinner;

    // --- LM Studio ---
    private JTextField lmBaseUrlField;
    private JComboBox<String> lmModelCombo;
    private JButton lmRefreshButton;
    private volatile String lmLoadedModelId;
    private JSpinner lmMaxTokensSpinner;
    private JSpinner lmTemperatureSpinner;
    private JSpinner lmTimeoutSpinner;

    // --- OpenAI (ChatGPT) ---
    private JPasswordField openaiApiKeyField;
    private JTextField openaiBaseUrlField;
    private JTextField openaiModelField;
    private JSpinner openaiMaxTokensSpinner;
    private JSpinner openaiTemperatureSpinner;
    private JSpinner openaiTimeoutSpinner;

    // --- NVIDIA ---
    private JPasswordField nvidiaApiKeyField;
    private JTextField nvidiaBaseUrlField;
    private JTextField nvidiaModelField;
    private JSpinner nvidiaMaxTokensSpinner;
    private JSpinner nvidiaTemperatureSpinner;
    private JSpinner nvidiaTimeoutSpinner;

    // --- Ollama (local) ---
    private JTextField ollamaBaseUrlField;
    private JTextField ollamaModelField;
    private JSpinner ollamaMaxTokensSpinner;
    private JSpinner ollamaTemperatureSpinner;
    private JSpinner ollamaTimeoutSpinner;

    // --- llama.cpp (local) ---
    private JTextField llamacppBaseUrlField;
    private JTextField llamacppModelField;
    private JSpinner llamacppMaxTokensSpinner;
    private JSpinner llamacppTemperatureSpinner;
    private JSpinner llamacppTimeoutSpinner;

    // --- Behaviour ---
    private JComboBox<SanitizationMode> sanitizeCombo;

    private JLabel statusLabel;

    public ConfigPanel(MontoyaApi api, XagentConfig config, ConfigStore store, ProviderRegistry providers) {
        this.api = api;
        this.log = api.logging();
        this.config = config;
        this.store = store;
        this.providers = providers;
        buildUi();
        loadFromConfig();
    }

    private void buildUi() {
        setLayout(new BorderLayout());

        // Header (Burp disables HTML rendering in JLabels — use plain text + setFont/setForeground).
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        JLabel hTitle = new JLabel("Artificial Intelligence for Burp Suite - XagentAI");
        hTitle.setFont(hTitle.getFont().deriveFont(Font.BOLD, 16f));
        header.add(hTitle);
        JLabel hSub = new JLabel("v0.2.0 · xagentai.net");
        hSub.setForeground(new Color(0x808080));
        header.add(hSub);
        add(header, BorderLayout.NORTH);

        // Tabs
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Active provider", buildActiveProviderPanel());
        tabs.addTab("Claude", buildClaudePanel());
        tabs.addTab("OpenAI", buildOpenAiPanel());
        tabs.addTab("NVIDIA", buildNvidiaPanel());
        tabs.addTab("LM Studio", buildLMStudioPanel());
        tabs.addTab("Ollama", buildOllamaPanel());
        tabs.addTab("llama.cpp", buildLlamacppPanel());
        tabs.addTab("Behaviour", buildBehaviourPanel());
        tabs.addTab("About", buildAboutPanel());
        add(tabs, BorderLayout.CENTER);

        // Footer
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        statusLabel = new JLabel(" ");
        footer.add(statusLabel);
        JButton saveBtn = new JButton("Save settings");
        saveBtn.addActionListener(e -> saveSettings(true));
        footer.add(saveBtn);
        add(footer, BorderLayout.SOUTH);
    }

    private JPanel buildActiveProviderPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = baseConstraints();

        activeProviderCombo = new JComboBox<>();
        for (AIProvider pr : providers.all().values()) {
            activeProviderCombo.addItem(pr.id());
        }
        addRow(p, c, 0, "Active provider:", activeProviderCombo);

        JTextArea note = new JTextArea(
                "Pick which backend handles 'Analyze with AI' actions.\n\n"
                + "CLOUD providers (send data over the internet):\n"
                + "  • Claude — Anthropic API, requires an Anthropic API key.\n"
                + "  • OpenAI — ChatGPT API, requires an OpenAI API key.\n"
                + "  • NVIDIA — NIM / API Catalog, requires an NVIDIA API key.\n\n"
                + "LOCAL providers (nothing leaves this machine):\n"
                + "  • LM Studio — OpenAI-compatible endpoint on this machine.\n"
                + "  • Ollama — OpenAI-compatible endpoint (http://localhost:11434).\n"
                + "  • llama.cpp — llama-server OpenAI endpoint (http://localhost:8080).");
        note.setEditable(false);
        note.setOpaque(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        c.gridy = 1;
        c.gridx = 0;
        c.gridwidth = 2;
        p.add(note, c);

        return wrap(p);
    }

    private JPanel buildClaudePanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = baseConstraints();

        claudeApiKeyField = new JPasswordField(40);
        addRow(p, c, 0, "API key:", claudeApiKeyField);
        claudeBaseUrlField = new JTextField(40);
        addRow(p, c, 1, "Base URL:", claudeBaseUrlField);
        claudeModelCombo = new JComboBox<>(new String[] {
                "claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"
        });
        claudeModelCombo.setEditable(true);
        addRow(p, c, 2, "Model:", claudeModelCombo);
        claudeMaxTokensSpinner = new JSpinner(new SpinnerNumberModel(4096, 1, 1_000_000, 256));
        addRow(p, c, 3, "Max tokens:", claudeMaxTokensSpinner);
        claudeTemperatureSpinner = new JSpinner(new SpinnerNumberModel(0.2d, 0.0d, 2.0d, 0.1d));
        claudeTemperatureSpinner.setToolTipText("Ignored on Claude 5+ (Anthropic deprecated the 'temperature' parameter for the Claude 5 family).");
        addRow(p, c, 4, "Temperature:", claudeTemperatureSpinner);
        claudeTimeoutSpinner = new JSpinner(new SpinnerNumberModel(60, 1, 3600, 10));
        addRow(p, c, 5, "Timeout (s):", claudeTimeoutSpinner);

        JButton testBtn = new JButton("Test connection");
        testBtn.addActionListener(e -> runTest("claude"));
        c.gridy = 6;
        c.gridx = 1;
        c.gridwidth = 1;
        c.weightx = 0;
        p.add(testBtn, c);

        return wrap(p);
    }

    private JPanel buildLMStudioPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = baseConstraints();

        lmBaseUrlField = new JTextField(40);
        addRow(p, c, 0, "Base URL:", lmBaseUrlField);

        JPanel modelRow = new JPanel(new BorderLayout(4, 0));
        lmModelCombo = new JComboBox<>();
        lmModelCombo.setEditable(true);
        lmModelCombo.setToolTipText("Leave empty to auto-detect, or click Refresh to fetch models from LM Studio. The currently loaded model is shown in bold with '(loaded)'.");
        lmModelCombo.setRenderer(new LMModelCellRenderer());
        modelRow.add(lmModelCombo, BorderLayout.CENTER);
        lmRefreshButton = new JButton("Refresh");
        lmRefreshButton.setToolTipText("Fetch the list of models from LM Studio.");
        lmRefreshButton.addActionListener(e -> refreshLmModels());
        modelRow.add(lmRefreshButton, BorderLayout.EAST);
        addRow(p, c, 1, "Model:", modelRow);

        lmMaxTokensSpinner = new JSpinner(new SpinnerNumberModel(4096, 1, 1_000_000, 256));
        addRow(p, c, 2, "Max tokens:", lmMaxTokensSpinner);
        lmTemperatureSpinner = new JSpinner(new SpinnerNumberModel(0.2d, 0.0d, 2.0d, 0.1d));
        addRow(p, c, 3, "Temperature:", lmTemperatureSpinner);
        lmTimeoutSpinner = new JSpinner(new SpinnerNumberModel(300, 1, 3600, 10));
        addRow(p, c, 4, "Timeout (s):", lmTimeoutSpinner);

        JButton lmTestBtn = new JButton("Test connection");
        lmTestBtn.addActionListener(e -> runTest("lmstudio"));
        c.gridy = 5;
        c.gridx = 1;
        c.gridwidth = 1;
        c.weightx = 0;
        p.add(lmTestBtn, c);

        return wrap(p);
    }

    // =====================================================================
    // v0.2 providers: OpenAI, NVIDIA, Ollama, llama.cpp.
    // All share the same simple layout, built via buildSimpleProviderPanel().
    // =====================================================================

    private JPanel buildOpenAiPanel() {
        openaiApiKeyField = new JPasswordField(40);
        openaiBaseUrlField = new JTextField(40);
        openaiModelField = new JTextField(40);
        openaiMaxTokensSpinner = new JSpinner(new SpinnerNumberModel(4096, 1, 1_000_000, 256));
        openaiTemperatureSpinner = new JSpinner(new SpinnerNumberModel(0.2d, 0.0d, 2.0d, 0.1d));
        openaiTemperatureSpinner.setToolTipText("Ignored on GPT-5 / o1 / o3 / o4 reasoning models (OpenAI deprecated 'temperature' there).");
        openaiTimeoutSpinner = new JSpinner(new SpinnerNumberModel(90, 1, 3600, 10));
        return buildSimpleProviderPanel("openai", openaiApiKeyField, openaiBaseUrlField,
                openaiModelField, openaiMaxTokensSpinner, openaiTemperatureSpinner,
                openaiTimeoutSpinner, "e.g. gpt-4o-mini, gpt-4.1-mini, gpt-5-mini");
    }

    private JPanel buildNvidiaPanel() {
        nvidiaApiKeyField = new JPasswordField(40);
        nvidiaBaseUrlField = new JTextField(40);
        nvidiaModelField = new JTextField(40);
        nvidiaMaxTokensSpinner = new JSpinner(new SpinnerNumberModel(4096, 1, 1_000_000, 256));
        nvidiaTemperatureSpinner = new JSpinner(new SpinnerNumberModel(0.2d, 0.0d, 2.0d, 0.1d));
        nvidiaTimeoutSpinner = new JSpinner(new SpinnerNumberModel(90, 1, 3600, 10));
        return buildSimpleProviderPanel("nvidia", nvidiaApiKeyField, nvidiaBaseUrlField,
                nvidiaModelField, nvidiaMaxTokensSpinner, nvidiaTemperatureSpinner,
                nvidiaTimeoutSpinner, "e.g. nvidia/nemotron-3-nano-omni-30b-a3b-reasoning, meta/llama-4-scout-17b-16e-instruct");
    }

    private JPanel buildOllamaPanel() {
        ollamaBaseUrlField = new JTextField(40);
        ollamaModelField = new JTextField(40);
        ollamaMaxTokensSpinner = new JSpinner(new SpinnerNumberModel(4096, 1, 1_000_000, 256));
        ollamaTemperatureSpinner = new JSpinner(new SpinnerNumberModel(0.2d, 0.0d, 2.0d, 0.1d));
        ollamaTimeoutSpinner = new JSpinner(new SpinnerNumberModel(300, 1, 3600, 10));
        return buildSimpleProviderPanel("ollama", null, ollamaBaseUrlField,
                ollamaModelField, ollamaMaxTokensSpinner, ollamaTemperatureSpinner,
                ollamaTimeoutSpinner, "Leave empty to auto-detect via GET /v1/models. e.g. llama3.3, qwen2.5-coder");
    }

    private JPanel buildLlamacppPanel() {
        llamacppBaseUrlField = new JTextField(40);
        llamacppModelField = new JTextField(40);
        llamacppMaxTokensSpinner = new JSpinner(new SpinnerNumberModel(4096, 1, 1_000_000, 256));
        llamacppTemperatureSpinner = new JSpinner(new SpinnerNumberModel(0.2d, 0.0d, 2.0d, 0.1d));
        llamacppTimeoutSpinner = new JSpinner(new SpinnerNumberModel(300, 1, 3600, 10));
        return buildSimpleProviderPanel("llamacpp", null, llamacppBaseUrlField,
                llamacppModelField, llamacppMaxTokensSpinner, llamacppTemperatureSpinner,
                llamacppTimeoutSpinner, "Leave empty to use whatever llama-server loaded (usually fine).");
    }

    /** Shared layout for the simple OpenAI-compat sub-tabs. */
    private JPanel buildSimpleProviderPanel(String providerId,
                                            JPasswordField apiKeyField,  // null = no API key row (local)
                                            JTextField baseUrlField,
                                            JTextField modelField,
                                            JSpinner maxTokensSpinner,
                                            JSpinner temperatureSpinner,
                                            JSpinner timeoutSpinner,
                                            String modelTooltip) {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = baseConstraints();
        int y = 0;
        if (apiKeyField != null) {
            addRow(p, c, y++, "API key:", apiKeyField);
        }
        addRow(p, c, y++, "Base URL:", baseUrlField);
        if (modelTooltip != null) modelField.setToolTipText(modelTooltip);
        addRow(p, c, y++, "Model:", modelField);
        addRow(p, c, y++, "Max tokens:", maxTokensSpinner);
        addRow(p, c, y++, "Temperature:", temperatureSpinner);
        addRow(p, c, y++, "Timeout (s):", timeoutSpinner);

        JButton testBtn = new JButton("Test connection");
        testBtn.addActionListener(e -> runTest(providerId));
        c.gridy = y;
        c.gridx = 1;
        c.gridwidth = 1;
        c.weightx = 0;
        p.add(testBtn, c);

        return wrap(p);
    }

    private JPanel buildBehaviourPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = baseConstraints();

        sanitizeCombo = new JComboBox<>(SanitizationMode.values());
        sanitizeCombo.setToolTipText("<html>"
                + "<b>ACTIVE</b>: always redact Authorization / Cookie / API-key headers before sending to the AI, "
                + "even when the AI is a local model running on this machine.<br>"
                + "<b>INACTIVE</b>: never redact — the request is sent AS-IS to the AI (local or cloud).<br>"
                + "<b>AUTO</b> (default): send the request AS-IS to local models (LM Studio, Ollama, llama.cpp — "
                + "nothing leaves this machine, so nothing is redacted) and redact only when the active provider "
                + "is cloud-hosted (Claude, OpenAI, NVIDIA)."
                + "</html>");
        addRow(p, c, 0, "Sanitize PII (headers):", sanitizeCombo);

        JTextArea note = new JTextArea(
                "ACTIVE   — Always sanitize. Sensitive header values are redacted before the request\n"
              + "           is sent to the AI, even when the AI is a local model on this machine.\n\n"
              + "INACTIVE — Never sanitize. The full request is sent AS-IS to the AI (local or cloud).\n"
              + "           Use only when you want the AI to see the exact auth headers.\n\n"
              + "AUTO     — Sanitize only when the request leaves this machine.\n"
              + "           • Local providers (LM Studio, Ollama, llama.cpp): the request is sent\n"
              + "             AS-IS to the local model — nothing leaves your machine, nothing is\n"
              + "             redacted.\n"
              + "           • Cloud providers (Claude, OpenAI, NVIDIA): sensitive header VALUES are\n"
              + "             redacted before the request is sent over the internet.\n\n"
              + "Headers redacted when sanitization runs (VALUES are replaced with [REDACTED];\n"
              + "the header NAMES are kept so the model still sees that auth was present):\n\n"
              + "  Authorization, Proxy-Authorization, Cookie, Set-Cookie,\n"
              + "  X-Api-Key, X-Auth-Token, X-Amz-Security-Token, X-CSRF-Token");
        note.setEditable(false);
        note.setOpaque(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        c.gridy = 1;
        c.gridx = 0;
        c.gridwidth = 2;
        c.weightx = 1;
        p.add(note, c);

        return wrap(p);
    }

    private JPanel buildAboutPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.NONE;

        // Title (two columns wide)
        JLabel title = new JLabel("Artificial Intelligence for Burp Suite - XagentAI");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        c.gridx = 0; c.gridy = 0; c.gridwidth = 2;
        c.insets = new Insets(0, 0, 12, 0);
        p.add(title, c);

        c.gridwidth = 1;
        c.insets = new Insets(2, 0, 2, 12);

        // Metadata rows (label / value)
        c.gridx = 0; c.gridy = 1; p.add(boldLabel("Version:"), c);
        c.gridx = 1;              p.add(new JLabel("0.2.0"), c);

        c.gridx = 0; c.gridy = 2; p.add(boldLabel("Author:"), c);
        c.gridx = 1;              p.add(new JLabel("xagentai.net"), c);

        c.gridx = 0; c.gridy = 3; p.add(boldLabel("License:"), c);
        c.gridx = 1;              p.add(new JLabel("Apache-2.0"), c);

        // Description block (JTextArea because Burp strips HTML out of JLabel).
        JTextArea desc = new JTextArea(
                "Brings multiple AI providers directly into the Burp Suite workflow.\n"
              + "Right-click any request (Proxy History, Repeater, Intruder, Scanner Issues,\n"
              + "Target Site Map or WebSocket History) → Extensions → Artificial Intelligence\n"
              + "for Burp Suite - XagentAI → Analyze with AI.\n\n"
              + "SUPPORTED PROVIDERS\n"
              + "  Cloud  Claude (Anthropic), OpenAI (ChatGPT), NVIDIA (NIM / API Catalog).\n"
              + "  Local  LM Studio, Ollama, llama.cpp — nothing leaves your machine.\n\n"
              + "RESULT DIALOG\n"
              + "  • Analysis rendered from Markdown to HTML.\n"
              + "  • Send to Repeater — the AI turns each proposed test into a real HTTP\n"
              + "    request and each one opens in its own Repeater tab (falls back to the\n"
              + "    original request when no tests were proposed).\n"
              + "  • Send to Intruder — the AI picks the best §-marked position, opens\n"
              + "    Intruder with the positions already set, and copies the payload list\n"
              + "    to the clipboard, ready to paste into the Payloads tab.\n"
              + "  • Copy as Markdown — copies the raw analysis to the clipboard.\n\n"
              + "PRIVACY\n"
              + "  Sanitize PII combo (Active / Inactive / Auto). In Auto, sensitive header\n"
              + "  values (Authorization, Cookie, API-key headers) are redacted only when\n"
              + "  the active provider is cloud-hosted; local providers always receive the\n"
              + "  request as-is since nothing leaves the machine.");
        desc.setEditable(false);
        desc.setOpaque(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setFont(new JLabel().getFont());

        c.gridwidth = 2;
        c.gridx = 0;
        c.gridy = 4;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(14, 0, 2, 0);
        p.add(desc, c);

        // Filler to push everything to the top-left.
        c.gridy = 5;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        c.insets = new Insets(0, 0, 0, 0);
        p.add(new JPanel(), c);

        return p;
    }

    private JLabel boldLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD));
        return l;
    }

    private void loadFromConfig() {
        activeProviderCombo.setSelectedItem(config.activeProviderId());
        claudeApiKeyField.setText(config.claudeApiKey());
        claudeBaseUrlField.setText(config.claudeBaseUrl());
        claudeModelCombo.setSelectedItem(config.claudeModel());
        claudeMaxTokensSpinner.setValue(config.claudeMaxTokens());
        claudeTemperatureSpinner.setValue(config.claudeTemperature());
        claudeTimeoutSpinner.setValue(config.claudeTimeoutSeconds());
        lmBaseUrlField.setText(config.lmStudioBaseUrl());
        setLmSelectedModel(config.lmStudioModel());
        lmMaxTokensSpinner.setValue(config.lmStudioMaxTokens());
        lmTemperatureSpinner.setValue(config.lmStudioTemperature());
        lmTimeoutSpinner.setValue(config.lmStudioTimeoutSeconds());

        openaiApiKeyField.setText(config.openaiApiKey());
        openaiBaseUrlField.setText(config.openaiBaseUrl());
        openaiModelField.setText(config.openaiModel());
        openaiMaxTokensSpinner.setValue(config.openaiMaxTokens());
        openaiTemperatureSpinner.setValue(config.openaiTemperature());
        openaiTimeoutSpinner.setValue(config.openaiTimeoutSeconds());

        nvidiaApiKeyField.setText(config.nvidiaApiKey());
        nvidiaBaseUrlField.setText(config.nvidiaBaseUrl());
        nvidiaModelField.setText(config.nvidiaModel());
        nvidiaMaxTokensSpinner.setValue(config.nvidiaMaxTokens());
        nvidiaTemperatureSpinner.setValue(config.nvidiaTemperature());
        nvidiaTimeoutSpinner.setValue(config.nvidiaTimeoutSeconds());

        ollamaBaseUrlField.setText(config.ollamaBaseUrl());
        ollamaModelField.setText(config.ollamaModel());
        ollamaMaxTokensSpinner.setValue(config.ollamaMaxTokens());
        ollamaTemperatureSpinner.setValue(config.ollamaTemperature());
        ollamaTimeoutSpinner.setValue(config.ollamaTimeoutSeconds());

        llamacppBaseUrlField.setText(config.llamacppBaseUrl());
        llamacppModelField.setText(config.llamacppModel());
        llamacppMaxTokensSpinner.setValue(config.llamacppMaxTokens());
        llamacppTemperatureSpinner.setValue(config.llamacppTemperature());
        llamacppTimeoutSpinner.setValue(config.llamacppTimeoutSeconds());

        sanitizeCombo.setSelectedItem(config.sanitizationMode());
    }

    /** Collect UI state into {@link XagentConfig} and persist. Returns true on success. */
    private boolean saveSettings(boolean showToast) {
        try {
            config.activeProviderId((String) activeProviderCombo.getSelectedItem());
            config.claudeApiKey(new String(claudeApiKeyField.getPassword()));
            config.claudeBaseUrl(claudeBaseUrlField.getText().trim());
            Object m = claudeModelCombo.getSelectedItem();
            config.claudeModel(m == null ? "" : m.toString().trim());
            config.claudeMaxTokens((Integer) claudeMaxTokensSpinner.getValue());
            config.claudeTemperature(((Number) claudeTemperatureSpinner.getValue()).doubleValue());
            config.claudeTimeoutSeconds((Integer) claudeTimeoutSpinner.getValue());
            config.lmStudioBaseUrl(lmBaseUrlField.getText().trim());
            Object lmSel = lmModelCombo.getSelectedItem();
            config.lmStudioModel(lmSel == null ? "" : lmSel.toString().trim());
            config.lmStudioMaxTokens((Integer) lmMaxTokensSpinner.getValue());
            config.lmStudioTemperature(((Number) lmTemperatureSpinner.getValue()).doubleValue());
            config.lmStudioTimeoutSeconds((Integer) lmTimeoutSpinner.getValue());

            config.openaiApiKey(new String(openaiApiKeyField.getPassword()));
            config.openaiBaseUrl(openaiBaseUrlField.getText().trim());
            config.openaiModel(openaiModelField.getText().trim());
            config.openaiMaxTokens((Integer) openaiMaxTokensSpinner.getValue());
            config.openaiTemperature(((Number) openaiTemperatureSpinner.getValue()).doubleValue());
            config.openaiTimeoutSeconds((Integer) openaiTimeoutSpinner.getValue());

            config.nvidiaApiKey(new String(nvidiaApiKeyField.getPassword()));
            config.nvidiaBaseUrl(nvidiaBaseUrlField.getText().trim());
            config.nvidiaModel(nvidiaModelField.getText().trim());
            config.nvidiaMaxTokens((Integer) nvidiaMaxTokensSpinner.getValue());
            config.nvidiaTemperature(((Number) nvidiaTemperatureSpinner.getValue()).doubleValue());
            config.nvidiaTimeoutSeconds((Integer) nvidiaTimeoutSpinner.getValue());

            config.ollamaBaseUrl(ollamaBaseUrlField.getText().trim());
            config.ollamaModel(ollamaModelField.getText().trim());
            config.ollamaMaxTokens((Integer) ollamaMaxTokensSpinner.getValue());
            config.ollamaTemperature(((Number) ollamaTemperatureSpinner.getValue()).doubleValue());
            config.ollamaTimeoutSeconds((Integer) ollamaTimeoutSpinner.getValue());

            config.llamacppBaseUrl(llamacppBaseUrlField.getText().trim());
            config.llamacppModel(llamacppModelField.getText().trim());
            config.llamacppMaxTokens((Integer) llamacppMaxTokensSpinner.getValue());
            config.llamacppTemperature(((Number) llamacppTemperatureSpinner.getValue()).doubleValue());
            config.llamacppTimeoutSeconds((Integer) llamacppTimeoutSpinner.getValue());

            config.sanitizationMode((SanitizationMode) sanitizeCombo.getSelectedItem());
            store.save(config);
            if (showToast) flashStatus("Settings saved.", true);
            log.logToOutput("Settings saved. active=" + config.activeProviderId()
                    + " sanitization=" + config.sanitizationMode());
            return true;
        } catch (Exception ex) {
            flashStatus("Save failed: " + ex.getMessage(), false);
            log.logToError("Settings save failed: " + ex.getMessage());
            return false;
        }
    }

    private void runTest(String providerId) {
        if (!saveSettings(false)) return;
        AIProvider p = providers.byId(providerId);
        if (p == null) {
            flashStatus("Unknown provider: " + providerId, false);
            return;
        }
        if (!p.isConfigured()) {
            flashStatus(p.displayName() + " is not configured (missing API key / URL).", false);
            return;
        }
        flashStatus("Testing " + p.displayName() + "...", true);
        ExtensionLifecycle.startTracked(api, () -> {
            TestResult r = p.testConnection();
            SwingUtilities.invokeLater(() -> {
                String msg = p.displayName() + ": "
                        + (r.ok() ? "OK (" + r.latencyMillis() + " ms)" : "FAIL — " + r.message());
                flashStatus(msg, r.ok());
                if (!r.ok()) {
                    JOptionPane.showMessageDialog(this, r.message(),
                            "XagentAI — " + p.displayName() + " test failed", JOptionPane.WARNING_MESSAGE);
                }
            });
        }, "xagentai-test-" + providerId);
    }

    private void flashStatus(String msg, boolean ok) {
        if (ok) {
            statusLabel.setForeground(new Color(0x2E7D32)); // calm green for success
        } else {
            statusLabel.setForeground(null); // default theme color — no red
        }
        statusLabel.setText(msg);
    }

    /** Fetch models from LM Studio in a background thread and populate the combo. */
    private void refreshLmModels() {
        AIProvider p = providers.byId("lmstudio");
        if (!(p instanceof LMStudioProvider lm)) {
            flashStatus("LM Studio provider not available", false);
            return;
        }
        // Persist current UI values (so lm.config.lmStudioBaseUrl() is up to date).
        if (!saveSettings(false)) return;

        lmRefreshButton.setEnabled(false);
        flashStatus("Refreshing models from " + config.lmStudioBaseUrl() + "...", true);

        ExtensionLifecycle.startTracked(api, () -> {
            try {
                List<LMStudioProvider.ModelInfo> models = lm.listAvailableModels();
                SwingUtilities.invokeLater(() -> {
                    String previous = (String) lmModelCombo.getSelectedItem();
                    lmModelCombo.removeAllItems();
                    lmLoadedModelId = null;
                    String loaded = null;
                    // Loaded model first.
                    for (LMStudioProvider.ModelInfo m : models) {
                        if (m.loaded()) {
                            loaded = m.id();
                            lmLoadedModelId = m.id();
                            lmModelCombo.addItem(m.id());
                            break;
                        }
                    }
                    for (LMStudioProvider.ModelInfo m : models) {
                        if (!m.loaded()) lmModelCombo.addItem(m.id());
                    }
                    if (loaded != null) {
                        lmModelCombo.setSelectedItem(loaded);
                    } else if (previous != null && !previous.isEmpty()) {
                        setLmSelectedModel(previous);
                    }
                    flashStatus(models.size() + " model(s) found"
                            + (loaded != null ? " · loaded (bold): " + loaded : " · none currently loaded"), true);
                    lmRefreshButton.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    flashStatus("Refresh failed: " + ex.getMessage(), false);
                    lmRefreshButton.setEnabled(true);
                });
            }
        }, "xagentai-lm-refresh");
    }

    /** Ensure {@code modelId} is present in the combo and selected. */
    private void setLmSelectedModel(String modelId) {
        if (modelId == null) modelId = "";
        boolean present = false;
        for (int i = 0; i < lmModelCombo.getItemCount(); i++) {
            if (modelId.equals(lmModelCombo.getItemAt(i))) { present = true; break; }
        }
        if (!present && !modelId.isEmpty()) {
            lmModelCombo.insertItemAt(modelId, 0);
        }
        lmModelCombo.setSelectedItem(modelId);
    }

    /** Renders the loaded LM Studio model in bold with a "(loaded)" suffix. */
    private final class LMModelCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            Component c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof String s && lmLoadedModelId != null && s.equals(lmLoadedModelId)) {
                setText(s + "  (loaded)");
                setFont(c.getFont().deriveFont(Font.BOLD));
            } else {
                setFont(c.getFont().deriveFont(Font.PLAIN));
            }
            return c;
        }
    }

    private GridBagConstraints baseConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        return c;
    }

    private void addRow(JPanel p, GridBagConstraints c, int y, String label, Component field) {
        c.gridy = y;
        c.gridx = 0;
        c.weightx = 0;
        c.gridwidth = 1;
        p.add(new JLabel(label), c);
        c.gridx = 1;
        c.weightx = 1;
        p.add(field, c);
    }

    private JPanel wrap(JPanel inner) {
        JPanel out = new JPanel(new BorderLayout());
        out.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        out.add(inner, BorderLayout.NORTH);
        return out;
    }
}
