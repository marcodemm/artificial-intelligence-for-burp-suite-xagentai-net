package net.xagentai.burp.ai.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;

import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.AIException;
import net.xagentai.burp.ai.providers.AIProvider;
import net.xagentai.burp.ai.providers.AIRequest;
import net.xagentai.burp.ai.providers.AIResponse;
import net.xagentai.burp.ai.providers.ProviderRegistry;
import net.xagentai.burp.ai.util.HttpRequestSerializer;
import net.xagentai.burp.ai.util.Sanitizer;

import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Registers "Analyze with AI" (and "Analyze issue with AI" for scan issues)
 * across the supported Burp context menus. Implements the three default
 * methods of {@link ContextMenuItemsProvider}: HTTP, WebSocket, AuditIssue.
 *
 * On click: serialize the selection → sanitize headers (if enabled) → send
 * to the active provider in a background thread → show the response in
 * a {@link ResultDialog}.
 */
public final class XagentContextMenuProvider implements ContextMenuItemsProvider {

    private static final Set<InvocationType> SUPPORTED = Set.of(
            InvocationType.PROXY_HISTORY,
            InvocationType.PROXY_INTERCEPT,
            InvocationType.MESSAGE_EDITOR_REQUEST,
            InvocationType.MESSAGE_EDITOR_RESPONSE,
            InvocationType.MESSAGE_VIEWER_REQUEST,
            InvocationType.MESSAGE_VIEWER_RESPONSE,
            InvocationType.SITE_MAP_TREE,
            InvocationType.SITE_MAP_TABLE,
            InvocationType.INTRUDER_ATTACK_RESULTS,
            InvocationType.INTRUDER_PAYLOAD_POSITIONS,
            InvocationType.SCANNER_RESULTS,
            InvocationType.SEARCH_RESULTS
    );

    private static final String HTTP_SYSTEM_PROMPT =
            "You are a security analyst assisting a penetration tester inside Burp Suite.\n"
            + "Analyze the HTTP request/response below for security issues.\n\n"
            + "Respond in this structure:\n"
            + "1. ENDPOINT — one-line summary of what this endpoint does.\n"
            + "2. AUTH — how authentication / authorization appears to work.\n"
            + "3. VULNERABILITIES — enumerate potential issues with brief rationale\n"
            + "   (OWASP Top 10, business logic, info leakage, insecure cookies/headers).\n"
            + "4. TESTS TO RUN — concrete next steps with exact payloads or request edits.\n"
            + "5. INTRUDER PAYLOADS — list of payloads to fuzz if useful.\n\n"
            + "Be concise, actionable, and specific. No disclaimers.";

    private static final String WS_SYSTEM_PROMPT =
            "You are a security analyst assisting a penetration tester inside Burp Suite.\n"
            + "Analyze the WebSocket messages below. The upgrade request is included for context.\n\n"
            + "Respond in this structure:\n"
            + "1. STREAM PURPOSE — what this WebSocket channel appears to do.\n"
            + "2. MESSAGE FORMAT — structure of payloads (JSON schema, binary, framing).\n"
            + "3. AUTHZ — is the channel authenticated? Can messages be spoofed?\n"
            + "4. VULNERABILITIES — injection, broken authz, info leak, race conditions.\n"
            + "5. TESTS TO RUN — concrete messages to try, with exact payloads.\n\n"
            + "Be concise, actionable, and specific. No disclaimers.";

    private static final String ISSUE_SYSTEM_PROMPT =
            "You are a security analyst assisting a penetration tester inside Burp Suite.\n"
            + "The user selected one or more findings from Burp Scanner. Analyze them.\n\n"
            + "Respond in this structure:\n"
            + "1. SUMMARY — one line per issue.\n"
            + "2. REAL IMPACT — what could an attacker actually do? Rate 1-5.\n"
            + "3. VERIFICATION — exact steps / requests to confirm the issue is exploitable.\n"
            + "4. ESCALATION — ways to chain or increase impact.\n"
            + "5. REMEDIATION — concrete fix for the dev team.\n\n"
            + "Be concise, actionable, and specific. No disclaimers.";

    private final MontoyaApi api;
    private final Logging log;
    private final XagentConfig config;
    private final ProviderRegistry providers;

    public XagentContextMenuProvider(MontoyaApi api, XagentConfig config, ProviderRegistry providers) {
        this.api = api;
        this.log = api.logging();
        this.config = config;
        this.providers = providers;
    }

    // ---- HTTP context menu ----

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (!SUPPORTED.contains(event.invocationType())) {
            return List.of();
        }
        List<Component> items = new ArrayList<>();
        JMenuItem analyze = new JMenuItem("Analyze with AI");
        analyze.addActionListener(e -> onAnalyzeHttp(event));
        items.add(analyze);
        return items;
    }

    private void onAnalyzeHttp(ContextMenuEvent event) {
        HttpRequestResponse rr = resolveHttpSelection(event);
        if (rr == null) {
            showWarn("No HTTP request/response selected.");
            return;
        }
        AIProvider provider = providers.active();
        String content = HttpRequestSerializer.serialize(rr);
        if (Sanitizer.shouldRedact(config.sanitizationMode(), provider.kind())) {
            content = Sanitizer.redactHeaders(content);
        }
        String systemPrompt = effectiveSystemPrompt(HTTP_SYSTEM_PROMPT);
        String userMessage = "Analyze the following HTTP exchange:\n\n" + content;
        askAndShow(provider, systemPrompt, userMessage, "PROXY/HTTP", rr.request());
    }

    private HttpRequestResponse resolveHttpSelection(ContextMenuEvent event) {
        Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
        if (editor.isPresent()) {
            return editor.get().requestResponse();
        }
        List<HttpRequestResponse> list = event.selectedRequestResponses();
        if (list != null && !list.isEmpty()) {
            return list.get(0);
        }
        return null;
    }

    // ---- WebSocket context menu ----

    @Override
    public List<Component> provideMenuItems(WebSocketContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        JMenuItem analyze = new JMenuItem("Analyze with AI");
        analyze.addActionListener(e -> onAnalyzeWebSocket(event));
        items.add(analyze);
        return items;
    }

    private void onAnalyzeWebSocket(WebSocketContextMenuEvent event) {
        List<WebSocketMessage> msgs = new ArrayList<>();
        if (event.messageEditorWebSocket().isPresent()) {
            WebSocketMessage m = event.messageEditorWebSocket().get().webSocketMessage();
            if (m != null) msgs.add(m);
        }
        if (msgs.isEmpty()) {
            msgs.addAll(event.selectedWebSocketMessages());
        }
        if (msgs.isEmpty()) {
            showWarn("No WebSocket messages selected.");
            return;
        }
        AIProvider provider = providers.active();
        String content = HttpRequestSerializer.serializeWebSocketMessages(msgs, HttpRequestSerializer.DEFAULT_MAX_CHARS);
        // Sanitizer only affects the upgrade request headers, but that's where auth tokens live.
        if (Sanitizer.shouldRedact(config.sanitizationMode(), provider.kind())) {
            content = Sanitizer.redactHeaders(content);
        }
        String systemPrompt = effectiveSystemPrompt(WS_SYSTEM_PROMPT);
        String userMessage = "Analyze the following WebSocket messages:\n\n" + content;
        // Pass the upgrade request so "Send to Repeater" from the dialog works.
        HttpRequest upgrade = msgs.isEmpty() ? null : msgs.get(0).upgradeRequest();
        askAndShow(provider, systemPrompt, userMessage, "WEBSOCKET", upgrade);
    }

    // ---- Scanner / Audit issue context menu ----

    @Override
    public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        JMenuItem analyze = new JMenuItem("Analyze issue with AI");
        analyze.addActionListener(e -> onAnalyzeAuditIssue(event));
        items.add(analyze);
        return items;
    }

    private void onAnalyzeAuditIssue(AuditIssueContextMenuEvent event) {
        List<AuditIssue> issues = event.selectedIssues();
        if (issues == null || issues.isEmpty()) {
            showWarn("No scan issues selected.");
            return;
        }
        AIProvider provider = providers.active();
        String content = HttpRequestSerializer.serializeAuditIssues(issues, HttpRequestSerializer.DEFAULT_MAX_CHARS);
        if (Sanitizer.shouldRedact(config.sanitizationMode(), provider.kind())) {
            content = Sanitizer.redactHeaders(content);
        }
        String systemPrompt = effectiveSystemPrompt(ISSUE_SYSTEM_PROMPT);
        String userMessage = "Analyze the following Burp Scanner issue(s):\n\n" + content;
        // Pass the first evidence request, if available, so "Send to Repeater" works.
        HttpRequest evidence = null;
        if (!issues.get(0).requestResponses().isEmpty()) {
            evidence = issues.get(0).requestResponses().get(0).request();
        }
        askAndShow(provider, systemPrompt, userMessage, "AUDIT_ISSUE", evidence);
    }

    // ---- Common send / display pipeline ----

    private void askAndShow(AIProvider provider, String systemPrompt, String userMessage,
                            String context, HttpRequest originalRequest) {
        if (!provider.isConfigured()) {
            showWarn(provider.displayName() + " is not configured.\nOpen the XagentAI tab → "
                    + provider.displayName() + " to set it up.");
            return;
        }

        double temperature = temperatureFor(provider.id());
        int maxTokens = maxTokensFor(provider.id());
        AIRequest request = new AIRequest(systemPrompt, userMessage, maxTokens, temperature);

        JDialog waiting = showWaitingDialog(provider);
        log.logToOutput("[" + context + "] Sending to " + provider.displayName()
                + " (sanitization=" + config.sanitizationMode()
                + ", bytes=" + userMessage.length() + ")");

        Thread t = new Thread(() -> {
            long start = System.nanoTime();
            try {
                AIResponse response = provider.send(request);
                long ms = (System.nanoTime() - start) / 1_000_000L;
                SwingUtilities.invokeLater(() -> {
                    waiting.dispose();
                    log.logToOutput("[" + context + "] " + provider.displayName()
                            + " responded in " + ms + " ms"
                            + " (in=" + response.inputTokens() + " out=" + response.outputTokens() + ")");
                    new ResultDialog(api, config, provider, response, ms, originalRequest).setVisible(true);
                });
            } catch (AIException ex) {
                long ms = (System.nanoTime() - start) / 1_000_000L;
                SwingUtilities.invokeLater(() -> {
                    waiting.dispose();
                    log.logToError("[" + context + "] " + provider.displayName()
                            + " failed in " + ms + " ms: " + ex.getMessage());
                    JOptionPane.showMessageDialog(null,
                            provider.displayName() + " returned an error:\n\n" + ex.getMessage(),
                            "XagentAI — error", JOptionPane.WARNING_MESSAGE);
                });
            } catch (RuntimeException ex) {
                SwingUtilities.invokeLater(() -> {
                    waiting.dispose();
                    log.logToError("[" + context + "] unexpected error: " + ex);
                    JOptionPane.showMessageDialog(null,
                            "Unexpected error:\n\n" + ex.getMessage(),
                            "XagentAI — error", JOptionPane.WARNING_MESSAGE);
                });
            }
        }, "xagentai-analyze");
        t.setDaemon(true);
        t.start();
    }

    private JDialog showWaitingDialog(AIProvider provider) {
        JDialog d = new JDialog();
        d.setTitle("XagentAI — asking " + provider.displayName());
        d.setModal(false);
        d.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        d.setLayout(new BorderLayout(10, 10));

        JLabel label = new JLabel("Waiting for " + provider.displayName() + "...  0s");
        JPanel center = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        center.add(label);
        d.add(center, BorderLayout.CENTER);

        JProgressBar bar = new JProgressBar();
        bar.setIndeterminate(true);
        JPanel south = new JPanel(new BorderLayout());
        south.add(bar, BorderLayout.CENTER);
        d.add(south, BorderLayout.SOUTH);

        // Live "elapsed seconds" counter — useful feedback for slow local models.
        long startMs = System.currentTimeMillis();
        Timer ticker = new Timer(1000, e -> {
            long elapsed = (System.currentTimeMillis() - startMs) / 1000L;
            label.setText("Waiting for " + provider.displayName() + "...  " + elapsed + "s");
        });
        ticker.setRepeats(true);
        ticker.start();
        d.addWindowListener(new WindowAdapter() {
            @Override public void windowClosed(WindowEvent e) { ticker.stop(); }
        });

        d.setPreferredSize(new Dimension(420, 110));
        d.pack();
        d.setLocationRelativeTo(null);
        d.setVisible(true);
        return d;
    }

    private String effectiveSystemPrompt(String fallback) {
        String custom = config.systemPrompt();
        return (custom == null || custom.isBlank()) ? fallback : custom;
    }

    private double temperatureFor(String providerId) {
        if ("claude".equals(providerId))   return config.claudeTemperature();
        if ("lmstudio".equals(providerId)) return config.lmStudioTemperature();
        return 0.2d;
    }

    private int maxTokensFor(String providerId) {
        if ("claude".equals(providerId))   return config.claudeMaxTokens();
        if ("lmstudio".equals(providerId)) return config.lmStudioMaxTokens();
        return 4096;
    }

    private void showWarn(String message) {
        JOptionPane.showMessageDialog(null, message, "XagentAI", JOptionPane.WARNING_MESSAGE);
    }
}
