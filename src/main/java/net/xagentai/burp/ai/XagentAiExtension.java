package net.xagentai.burp.ai;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import net.xagentai.burp.ai.config.ConfigStore;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.ProviderRegistry;
import net.xagentai.burp.ai.ui.ConfigPanel;
import net.xagentai.burp.ai.ui.XagentContextMenuProvider;

import javax.swing.SwingUtilities;

/**
 * Entry point of the XagentAI Burp Suite extension.
 *
 * Burp discovers this class through the ServiceLoader descriptor at
 * {@code META-INF/services/burp.api.montoya.BurpExtension}.
 */
public final class XagentAiExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "Artificial Intelligence for Burp Suite - XagentAI";
    public static final String EXTENSION_VERSION = "0.1.0";

    private MontoyaApi api;
    private Logging log;
    private XagentConfig config;
    private ProviderRegistry providers;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.log = api.logging();

        api.extension().setName(EXTENSION_NAME);
        log.logToOutput(EXTENSION_NAME + " v" + EXTENSION_VERSION + " loading...");

        ConfigStore store = new ConfigStore(api);
        this.config = store.load();
        this.providers = ProviderRegistry.withDefaults(api, this.config);

        log.logToOutput("Active provider: " + providers.active().displayName()
                + " (sanitization = " + config.sanitizationMode() + ")");

        // Register the Settings tab on Burp's top bar.
        SwingUtilities.invokeLater(() -> {
            ConfigPanel panel = new ConfigPanel(api, config, store, providers);
            api.userInterface().registerSuiteTab("XagentAI", panel);
            log.logToOutput("Settings tab registered.");
        });

        // Register the right-click "Analyze with AI" menu across supported contexts.
        api.userInterface().registerContextMenuItemsProvider(
                new XagentContextMenuProvider(api, config, providers));
        log.logToOutput("Context menu provider registered.");

        log.logToOutput(EXTENSION_NAME + " loaded.");
    }
}
