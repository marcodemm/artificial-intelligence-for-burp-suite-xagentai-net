package net.xagentai.burp.ai.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;

import net.xagentai.burp.ai.ExtensionLifecycle;
import net.xagentai.burp.ai.config.XagentConfig;
import net.xagentai.burp.ai.providers.AIException;
import net.xagentai.burp.ai.providers.AIProvider;
import net.xagentai.burp.ai.providers.AIRequest;
import net.xagentai.burp.ai.providers.AIResponse;

import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Modeless dialog that shows the AI response (rendered from Markdown to HTML).
 * Footer actions (left → right): Send to Repeater, Send to Intruder,
 * Copy as Markdown, Close.
 *
 * "Send to Repeater" asks the AI a second time to convert the TESTS TO RUN
 * of its previous answer into real HTTP requests, parses the blocks, and
 * sends each one to Repeater in its own tab. If the AI did not propose any
 * tests, it falls back to sending the ORIGINAL request to a single Repeater
 * tab.
 */
public final class ResultDialog extends JDialog {

    private static final String CONVERT_SYSTEM_PROMPT =
            "You previously analyzed an HTTP request/response and suggested TESTS TO RUN.\n"
            + "Now convert each test into a complete HTTP request in wire format, ready to\n"
            + "send with Burp Repeater.\n\n"
            + "MANDATORY OUTPUT CONTRACT. Your entire response MUST be ONLY a sequence of\n"
            + "blocks that match this shape, with the === TEST: and === END TEST === markers\n"
            + "written VERBATIM (three equals signs, one space, the word TEST, a colon):\n\n"
            + "=== TEST: <short descriptive name, max 40 chars, no colons> ===\n"
            + "<METHOD> <path-with-query> HTTP/1.1\n"
            + "Host: <host>\n"
            + "<other headers, one per line>\n"
            + "\n"
            + "<body if any, otherwise leave this line empty>\n"
            + "=== END TEST ===\n\n"
            + "WORKED EXAMPLE (emit output that looks EXACTLY like this — no Markdown\n"
            + "fences, no prose, no numbering around the blocks):\n\n"
            + "=== TEST: Reflected XSS in q parameter ===\n"
            + "GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
            + "Host: example.com\n"
            + "User-Agent: Mozilla/5.0\n"
            + "Accept: */*\n"
            + "\n"
            + "=== END TEST ===\n"
            + "=== TEST: Auth bypass via X-Forwarded-For ===\n"
            + "GET /admin HTTP/1.1\n"
            + "Host: example.com\n"
            + "X-Forwarded-For: 127.0.0.1\n"
            + "\n"
            + "=== END TEST ===\n\n"
            + "Rules:\n"
            + "- Base each test on the ORIGINAL request. Keep its host, cookies and auth\n"
            + "  headers UNLESS the test specifically needs to modify them.\n"
            + "- Produce ONE concrete request per test. If a test suggests several payloads,\n"
            + "  emit ONE block per payload with a numbered descriptive name.\n"
            + "- Do NOT emit prose, Markdown fences (```), bullet lists, numbered sections,\n"
            + "  headings or ANY commentary outside the === TEST === blocks.\n"
            + "- Use HTTP/1.1. There MUST be a blank line between the header block and the\n"
            + "  body (even when there is no body). This is required by the HTTP spec;\n"
            + "  without it the request will time out at the server.\n"
            + "- If there is a body, include an accurate Content-Length header.\n"
            + "- Do NOT emit destructive tests (DELETE / PUT on admin paths) unless the\n"
            + "  ORIGINAL request already used that method.";

    private static final Pattern TEST_BLOCK =
            Pattern.compile("=== TEST:\\s*(.+?)\\s*===\\s*\\r?\\n(.*?)\\r?\\n?=== END TEST ===",
                    Pattern.DOTALL);

    private static final String INTRUDER_SYSTEM_PROMPT =
            "You previously analyzed an HTTP request and suggested INTRUDER PAYLOADS.\n"
            + "Now output two blocks so Burp Intruder can be opened automatically:\n"
            + "  1. The ORIGINAL request with the best insertion point(s) wrapped in '§'\n"
            + "     (section-sign, U+00A7) as BOTH the opening and closing marker.\n"
            + "     Example: to fuzz header 'X-Foo: bar', write 'X-Foo: §bar§'.\n"
            + "     Pick ONE insertion point unless the analysis clearly needs several.\n"
            + "  2. The list of payloads, ONE PER LINE, no numbering, no extra text.\n\n"
            + "Format (exact — no other output):\n\n"
            + "=== INTRUDER REQUEST ===\n"
            + "<METHOD> <path> HTTP/1.1\n"
            + "Host: <host>\n"
            + "<other headers, with §...§ around the value to fuzz>\n"
            + "\n"
            + "<body if any, with §...§ markers if that is the fuzz target>\n"
            + "=== END REQUEST ===\n"
            + "=== PAYLOADS ===\n"
            + "payload1\n"
            + "payload2\n"
            + "...\n"
            + "=== END PAYLOADS ===\n\n"
            + "Rules:\n"
            + "- Keep ALL original headers unchanged except where you place a § marker.\n"
            + "- There MUST be a blank line between headers and body.\n"
            + "- Produce 5 to 50 payloads.\n"
            + "- Do NOT emit prose, commentary or Markdown outside the two blocks.";

    private static final Pattern INTRUDER_REQUEST_BLOCK =
            Pattern.compile("=== INTRUDER REQUEST ===\\s*\\r?\\n(.*?)\\r?\\n?=== END REQUEST ===",
                    Pattern.DOTALL);
    private static final Pattern INTRUDER_PAYLOADS_BLOCK =
            Pattern.compile("=== PAYLOADS ===\\s*\\r?\\n(.*?)\\r?\\n?=== END PAYLOADS ===",
                    Pattern.DOTALL);

    private final MontoyaApi api;
    private final XagentConfig config;
    private final AIProvider provider;
    private final HttpRequest originalRequest;
    private final String rawMarkdown;

    public ResultDialog(MontoyaApi api,
                        XagentConfig config,
                        AIProvider provider,
                        AIResponse response,
                        long latencyMs,
                        HttpRequest originalRequest) {

        this.api = api;
        this.config = config;
        this.provider = provider;
        this.originalRequest = originalRequest;
        this.rawMarkdown = nullSafe(response.content(), "");

        setTitle("XagentAI — " + provider.displayName());
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setModal(false);
        setPreferredSize(new Dimension(880, 640));
        setLayout(new BorderLayout(10, 10));

        // --- Header: metadata (gray, muted) ---
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        String info = "Model: " + nullSafe(response.modelId(), "unknown");
        if (response.inputTokens() >= 0 || response.outputTokens() >= 0) {
            info += "   ·   In: " + response.inputTokens() + " tok   ·   Out: " + response.outputTokens() + " tok";
        }
        info += "   ·   Latency: " + latencyMs + " ms";
        JLabel infoLabel = new JLabel(info);
        infoLabel.setForeground(new Color(0x808080));
        header.add(infoLabel);
        add(header, BorderLayout.NORTH);

        // --- Content: HTML rendered from Markdown ---
        JEditorPane pane = new JEditorPane();
        pane.setContentType("text/html");
        pane.setEditable(false);
        pane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        pane.setText(renderMarkdown(rawMarkdown));
        pane.setCaretPosition(0);
        pane.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        JScrollPane scroll = new JScrollPane(pane);
        scroll.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
        add(scroll, BorderLayout.CENTER);

        // --- Footer: action buttons (left → right) ---
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));

        if (originalRequest != null) {
            // "Send to Repeater" asks the AI to turn each TESTS TO RUN item of
            // the previous analysis into a real HTTP request and opens each
            // one in its own Repeater tab. When the analysis has no tests,
            // it falls back to sending the ORIGINAL request to a Repeater tab.
            JButton repeaterBtn = new JButton("Send to Repeater");
            repeaterBtn.setToolTipText("Ask the AI to turn the TESTS TO RUN into real HTTP requests and open each in its own Repeater tab. If no tests were proposed, sends the original request instead.");
            repeaterBtn.addActionListener(e -> sendProposedTests(repeaterBtn));
            footer.add(repeaterBtn);

            JButton intruderBtn = new JButton("Send to Intruder");
            intruderBtn.setToolTipText("Ask the AI to pick the best §...§ position and payload list, open Intruder with the positions already marked, and copy the payloads to the clipboard.");
            intruderBtn.addActionListener(e -> sendProposedIntruder(intruderBtn));
            footer.add(intruderBtn);
        }

        JButton copyBtn = new JButton("Copy as Markdown");
        copyBtn.setToolTipText("Copy the raw Markdown to the clipboard (ready to paste in a report).");
        copyBtn.addActionListener(e -> {
            try {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(rawMarkdown), null);
                flashButton(copyBtn, "Copied!", "Copy as Markdown");
            } catch (Exception ex) {
                flashButton(copyBtn, "Copy failed", "Copy as Markdown");
            }
        });
        footer.add(copyBtn);

        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        footer.add(closeBtn);
        add(footer, BorderLayout.SOUTH);

        // ESC closes
        getRootPane().registerKeyboardAction(
                e -> dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        getRootPane().setDefaultButton(closeBtn);

        pack();
        setLocationRelativeTo(ExtensionLifecycle.suiteFrame());
    }

    // ---------------------------------------------------------------------
    // Send Proposed: 2nd AI call → parse blocks → send to Repeater
    // ---------------------------------------------------------------------

    private void sendProposedTests(JButton btn) {
        if (originalRequest == null) return;
        if (!provider.isConfigured()) {
            JOptionPane.showMessageDialog(this,
                    provider.displayName() + " is not configured.",
                    "XagentAI", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String origWire = new String(originalRequest.toByteArray().getBytes(), StandardCharsets.UTF_8);
        String userMessage =
                "ORIGINAL REQUEST:\n\n" + origWire + "\n\n"
              + "PREVIOUS ANALYSIS:\n\n" + rawMarkdown;

        int maxTokens = Math.max(8192, maxTokensForProvider());
        AIRequest req = new AIRequest(CONVERT_SYSTEM_PROMPT, userMessage, maxTokens, 0.1d);

        btn.setEnabled(false);
        AtomicBoolean cancelled = new AtomicBoolean(false);
        AtomicReference<Thread> worker = new AtomicReference<>();
        JDialog waiting = showProposedWaitingDialog(btn, cancelled, worker);

        Thread t = ExtensionLifecycle.startTracked(api, () -> {
            try {
                AIResponse resp = provider.send(req);
                List<TestBlock> tests = parseTestBlocks(resp.content());
                SwingUtilities.invokeLater(() -> {
                    waiting.dispose();
                    if (cancelled.get()) {
                        api.logging().logToOutput("[SEND TO REPEATER] cancelled by operator; "
                                + provider.displayName() + " response discarded.");
                        return;
                    }
                    handleParsedTests(tests, resp.content(), btn);
                });
            } catch (AIException ex) {
                SwingUtilities.invokeLater(() -> {
                    waiting.dispose();
                    if (cancelled.get()) {
                        api.logging().logToOutput("[SEND TO REPEATER] cancelled; error suppressed: "
                                + ex.getMessage());
                        return;
                    }
                    btn.setEnabled(true);
                    JOptionPane.showMessageDialog(ResultDialog.this,
                            provider.displayName() + " error:\n\n" + ex.getMessage(),
                            "XagentAI — error", JOptionPane.WARNING_MESSAGE);
                });
            } catch (RuntimeException ex) {
                SwingUtilities.invokeLater(() -> {
                    waiting.dispose();
                    if (cancelled.get()) {
                        api.logging().logToOutput("[SEND TO REPEATER] cancelled; unexpected error suppressed: " + ex);
                        return;
                    }
                    btn.setEnabled(true);
                    JOptionPane.showMessageDialog(ResultDialog.this,
                            "Unexpected error:\n\n" + ex.getMessage(),
                            "XagentAI — error", JOptionPane.WARNING_MESSAGE);
                });
            }
        }, "xagentai-send-proposed");
        worker.set(t);
    }

    private void handleParsedTests(List<TestBlock> tests, String rawAiOutput, JButton btn) {
        btn.setEnabled(true);
        if (tests.isEmpty()) {
            // No TESTS TO RUN parsed → do NOT open any Repeater tab. The
            // previous behaviour sent the original request to a fresh tab
            // as a 'fallback', but that tab was useless (the operator
            // already has the original in Proxy History) and polluted the
            // Repeater panel. Instead, warn the operator and copy the raw
            // AI output to the clipboard when it is not empty.
            String clipboardLine;
            if (rawAiOutput == null || rawAiOutput.isEmpty()) {
                api.logging().logToOutput("[SEND TO REPEATER] AI returned empty content; "
                        + "no Repeater tab opened.");
                clipboardLine = "The AI returned an EMPTY response — nothing to copy to the clipboard.";
            } else {
                try {
                    Toolkit.getDefaultToolkit().getSystemClipboard()
                            .setContents(new StringSelection(rawAiOutput), null);
                    api.logging().logToOutput("[SEND TO REPEATER] no parseable === TEST === blocks; "
                            + "copied " + rawAiOutput.length() + " chars of raw AI output to clipboard; "
                            + "no Repeater tab opened.");
                    clipboardLine = "The raw AI output (" + rawAiOutput.length()
                            + " chars) has been copied to the clipboard so you can inspect it.";
                } catch (Exception ex) {
                    api.logging().logToError("[SEND TO REPEATER] clipboard copy failed: "
                            + ex.getMessage());
                    clipboardLine = "Failed to copy raw AI output to the clipboard: " + ex.getMessage();
                }
            }
            flashButton(btn, "No tests — nothing opened", "Send to Repeater");

            JOptionPane.showMessageDialog(this,
                    "The AI did not produce parseable === TEST === blocks, "
                  + "so NO Repeater tab was opened.\n\n"
                  + clipboardLine + "\n\n"
                  + "Why this happens:\n"
                  + "  • Small or local models sometimes ignore the strict TEST block format "
                  + "and reply in free-form Markdown instead.\n"
                  + "  • Reasoning models (nemotron super, qwen3-kimi, OpenAI o-series) can "
                  + "burn the entire token budget 'thinking' and leave the actual answer empty "
                  + "— check the extension Output log for the finish_reason and the keys of "
                  + "the message object.\n\n"
                  + "What to try:\n"
                  + "  • Raise the Max tokens field in the active provider's Settings tab "
                  + "(reasoning models need headroom: try 16384 or 32768).\n"
                  + "  • Switch to a stronger / non-reasoning model for the Send to Repeater "
                  + "step specifically.",
                    "XagentAI — no tests produced", JOptionPane.WARNING_MESSAGE);
            return;
        }

        HttpService svc = originalRequest.httpService();
        int sent = 0;
        List<String> failed = new ArrayList<>();
        for (TestBlock tb : tests) {
            try {
                String wire = normalizeHttpWireFormat(tb.body);
                HttpRequest r = HttpRequest.httpRequest(svc, wire);
                String tabName = "XagentAI: " + truncate(tb.name, 40);
                api.repeater().sendToRepeater(r, tabName);
                sent++;
            } catch (Exception ex) {
                failed.add(tb.name + " → " + ex.getMessage());
            }
        }
        flashButton(btn, "Sent " + sent + " tests!", "Send to Repeater");
        api.logging().logToOutput("[SEND TO REPEATER] " + sent + " tests sent to Repeater, "
                + failed.size() + " failed.");
        if (!failed.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            sb.append(sent).append(" test(s) opened in Repeater tabs named 'XagentAI: ...'.\n\n");
            sb.append(failed.size()).append(" test(s) failed to parse as a valid HTTP request:\n");
            for (String f : failed) {
                sb.append("  • ").append(f).append('\n');
            }
            JOptionPane.showMessageDialog(this, sb.toString(),
                    "XagentAI — partial success", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private JDialog showProposedWaitingDialog(JButton callerBtn,
                                              AtomicBoolean cancelled,
                                              AtomicReference<Thread> worker) {
        JDialog d = new JDialog(this, "XagentAI — generating tests", false);
        d.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        d.setLayout(new BorderLayout(10, 10));
        ExtensionLifecycle.trackWindow(d);

        JLabel label = new JLabel("Asking " + provider.displayName() + " to convert TESTS TO RUN into HTTP requests...  0s");
        JPanel center = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        center.add(label);
        d.add(center, BorderLayout.CENTER);

        JProgressBar bar = new JProgressBar();
        bar.setIndeterminate(true);
        JPanel south = new JPanel(new BorderLayout(6, 6));
        south.add(bar, BorderLayout.CENTER);

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.setToolTipText("Close this dialog and discard the AI's answer when it arrives. "
                + "Note: the HTTP request already in flight cannot be aborted mid-way; its result "
                + "will simply be ignored.");
        Runnable doCancel = () -> {
            if (cancelled.compareAndSet(false, true)) {
                Thread w = worker.get();
                if (w != null) w.interrupt();
                if (callerBtn != null) callerBtn.setEnabled(true);
            }
            d.dispose();
        };
        cancelBtn.addActionListener(e -> doCancel.run());
        south.add(cancelBtn, BorderLayout.EAST);
        d.add(south, BorderLayout.SOUTH);

        long startMs = System.currentTimeMillis();
        Timer ticker = new Timer(1000, e -> {
            long elapsed = (System.currentTimeMillis() - startMs) / 1000L;
            label.setText("Asking " + provider.displayName() + "... " + elapsed + "s");
        });
        ticker.start();
        d.addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) { doCancel.run(); }
            @Override public void windowClosed(WindowEvent e) { ticker.stop(); }
        });

        d.setPreferredSize(new Dimension(560, 140));
        d.pack();
        d.setLocationRelativeTo(this);
        d.setVisible(true);
        return d;
    }

    static List<TestBlock> parseTestBlocks(String text) {
        List<TestBlock> out = new ArrayList<>();
        if (text == null || text.isBlank()) return out;
        Matcher m = TEST_BLOCK.matcher(text);
        while (m.find()) {
            String name = m.group(1).trim();
            String body = m.group(2).trim();
            if (!name.isEmpty() && !body.isEmpty()) {
                out.add(new TestBlock(name, body));
            }
        }
        return out;
    }

    private int maxTokensForProvider() {
        if ("claude".equals(provider.id()))   return config.claudeMaxTokens();
        if ("lmstudio".equals(provider.id())) return config.lmStudioMaxTokens();
        return 4096;
    }

    /**
     * Guarantee the HTTP wire-format has CRLF line endings and the mandatory
     * blank line between the header block and the body — even when the model
     * forgets to include it. Without that blank line Burp shows "The HTTP
     * header block doesn't have a blank line at the end" and the request
     * times out at the server waiting for more headers.
     */
    static String normalizeHttpWireFormat(String wire) {
        if (wire == null || wire.isEmpty()) return "";
        // Trim trailing whitespace/newlines so we can append exactly what we need.
        String s = wire.replaceAll("\\s+$", "");
        // Normalize to LF for parsing, re-emit CRLF on output.
        s = s.replace("\r\n", "\n").replace("\r", "\n");
        int sep = s.indexOf("\n\n");
        String headers;
        String body;
        if (sep < 0) {
            headers = s;
            body = "";
        } else {
            headers = s.substring(0, sep);
            body = s.substring(sep + 2);
        }
        String headersCrlf = headers.replace("\n", "\r\n");
        String bodyCrlf = body.isEmpty() ? "" : body.replace("\n", "\r\n");
        return headersCrlf + "\r\n\r\n" + bodyCrlf;
    }

    static final class TestBlock {
        final String name;
        final String body;
        TestBlock(String name, String body) {
            this.name = name;
            this.body = body;
        }
    }

    // ---------------------------------------------------------------------
    // Send to Intruder: 2nd AI call → parse request+payloads → open Intruder
    //                   with §...§ positions marked + payloads on clipboard
    // ---------------------------------------------------------------------

    private void sendProposedIntruder(JButton btn) {
        if (originalRequest == null) return;
        if (!provider.isConfigured()) {
            JOptionPane.showMessageDialog(this,
                    provider.displayName() + " is not configured.",
                    "XagentAI", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String origWire = new String(originalRequest.toByteArray().getBytes(), StandardCharsets.UTF_8);
        String userMessage =
                "ORIGINAL REQUEST:\n\n" + origWire + "\n\n"
              + "PREVIOUS ANALYSIS:\n\n" + rawMarkdown;

        int maxTokens = Math.max(4096, maxTokensForProvider());
        AIRequest req = new AIRequest(INTRUDER_SYSTEM_PROMPT, userMessage, maxTokens, 0.1d);

        btn.setEnabled(false);
        AtomicBoolean cancelled = new AtomicBoolean(false);
        AtomicReference<Thread> worker = new AtomicReference<>();
        JDialog waiting = showProposedWaitingDialog(btn, cancelled, worker);

        Thread t = ExtensionLifecycle.startTracked(api, () -> {
            try {
                AIResponse resp = provider.send(req);
                SwingUtilities.invokeLater(() -> {
                    waiting.dispose();
                    if (cancelled.get()) {
                        api.logging().logToOutput("[SEND TO INTRUDER] cancelled by operator; "
                                + provider.displayName() + " response discarded.");
                        return;
                    }
                    btn.setEnabled(true);
                    handleIntruderResponse(resp.content(), btn);
                });
            } catch (AIException ex) {
                SwingUtilities.invokeLater(() -> {
                    waiting.dispose();
                    if (cancelled.get()) {
                        api.logging().logToOutput("[SEND TO INTRUDER] cancelled; error suppressed: "
                                + ex.getMessage());
                        return;
                    }
                    btn.setEnabled(true);
                    JOptionPane.showMessageDialog(ResultDialog.this,
                            provider.displayName() + " error:\n\n" + ex.getMessage(),
                            "XagentAI — error", JOptionPane.WARNING_MESSAGE);
                });
            } catch (RuntimeException ex) {
                SwingUtilities.invokeLater(() -> {
                    waiting.dispose();
                    if (cancelled.get()) {
                        api.logging().logToOutput("[SEND TO INTRUDER] cancelled; unexpected error suppressed: " + ex);
                        return;
                    }
                    btn.setEnabled(true);
                    JOptionPane.showMessageDialog(ResultDialog.this,
                            "Unexpected error:\n\n" + ex.getMessage(),
                            "XagentAI — error", JOptionPane.WARNING_MESSAGE);
                });
            }
        }, "xagentai-intruder");
        worker.set(t);
    }

    private void handleIntruderResponse(String aiOutput, JButton btn) {
        Matcher reqM = INTRUDER_REQUEST_BLOCK.matcher(aiOutput == null ? "" : aiOutput);
        Matcher payM = INTRUDER_PAYLOADS_BLOCK.matcher(aiOutput == null ? "" : aiOutput);
        if (!reqM.find()) {
            // Do NOT open an Intruder tab as a 'fallback' — a tab with no
            // §-positions is useless and clutters the panel. Mirror the
            // Send-to-Repeater guard: warn, copy the raw AI output to the
            // clipboard when non-empty, and point out that models can
            // refuse this prompt (seen in the wild with qwen/kimi-style
            // distilled models on real auth endpoints).
            String clipboardLine;
            if (aiOutput == null || aiOutput.isEmpty()) {
                api.logging().logToOutput("[INTRUDER] AI returned empty content; "
                        + "no Intruder tab opened.");
                clipboardLine = "The AI returned an EMPTY response — nothing to copy to the clipboard.";
            } else {
                try {
                    Toolkit.getDefaultToolkit().getSystemClipboard()
                            .setContents(new StringSelection(aiOutput), null);
                    api.logging().logToOutput("[INTRUDER] no parseable === INTRUDER REQUEST === block; "
                            + "copied " + aiOutput.length() + " chars of raw AI output to clipboard; "
                            + "no Intruder tab opened.");
                    clipboardLine = "The raw AI output (" + aiOutput.length()
                            + " chars) has been copied to the clipboard so you can inspect it.";
                } catch (Exception ex) {
                    api.logging().logToError("[INTRUDER] clipboard copy failed: " + ex.getMessage());
                    clipboardLine = "Failed to copy raw AI output to the clipboard: " + ex.getMessage();
                }
            }
            flashButton(btn, "No request block — not opened", "Send to Intruder");
            JOptionPane.showMessageDialog(this,
                    "The AI did not produce a parseable === INTRUDER REQUEST === block, "
                  + "so NO Intruder tab was opened.\n\n"
                  + clipboardLine + "\n\n"
                  + "Why this happens:\n"
                  + "  • Small or local models sometimes reply in free-form Markdown instead "
                  + "of the strict request/payloads block format.\n"
                  + "  • Reasoning models can burn the entire budget 'thinking' and leave "
                  + "the actual answer empty.\n"
                  + "  • Some distilled models (qwen-kimi, etc.) REFUSE to generate fuzzing "
                  + "payloads for live auth endpoints as an alignment safety behaviour — check "
                  + "the clipboard output; if it looks like a textual refusal, that's it.\n\n"
                  + "What to try:\n"
                  + "  • Switch to a less-restrictive model (Claude, OpenAI, or a vanilla "
                  + "instruct local model without alignment fine-tuning) for the Send to "
                  + "Intruder step.\n"
                  + "  • Raise Max tokens or lower Reasoning Budget in the active provider's "
                  + "Settings tab if the raw output is truncated mid-answer.",
                    "XagentAI — no Intruder request produced", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String wireWithMarkers = normalizeHttpWireFormat(reqM.group(1));
        ParsedWire parsed = extractRangesFromMarkers(wireWithMarkers);

        // Parse the payload list BEFORE deciding to open Intruder — an
        // Intruder tab with §-positions but no payloads is useless and
        // just clutters the operator's Intruder panel. If the AI produced
        // positions but no PAYLOADS block (small reasoning models and
        // some local models drop the second block), tell the operator and
        // do NOT open the tab.
        String payloadsBlock = null;
        int payloadsCopied = 0;
        if (payM.find()) {
            String raw = payM.group(1).trim();
            if (!raw.isEmpty()) {
                payloadsBlock = raw;
                payloadsCopied = (int) raw.lines().filter(l -> !l.isBlank()).count();
            }
        }
        if (payloadsCopied == 0) {
            api.logging().logToOutput("[INTRUDER] AI returned " + parsed.offsets.size()
                    + " §-position(s) but no payloads; Intruder tab NOT opened.");
            flashButton(btn, "No payloads — not opened", "Send to Intruder");
            JOptionPane.showMessageDialog(this,
                    "The AI marked " + parsed.offsets.size()
                  + " §-position(s) but did not produce a payload list.\n\n"
                  + "A Burp Intruder tab with insertion points but no payloads is not useful, "
                  + "so no tab was opened.\n\n"
                  + "Try Send to Intruder again (local / reasoning models sometimes drop the "
                  + "=== PAYLOADS === block), or switch to a stronger model in the active "
                  + "provider's Settings tab.",
                    "XagentAI — no payloads produced", JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<Range> ranges = new ArrayList<>();
        for (int[] p : parsed.offsets) {
            ranges.add(Range.range(p[0], p[1]));
        }

        HttpService svc = originalRequest.httpService();
        try {
            ByteArray content = ByteArray.byteArray(parsed.contentBytes);
            HttpRequestTemplate template = HttpRequestTemplate.httpRequestTemplate(content, ranges);
            api.intruder().sendToIntruder(svc, template, "XagentAI");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Failed to open Intruder: " + ex.getMessage(),
                    "XagentAI — error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(payloadsBlock), null);
        } catch (Exception ex) {
            api.logging().logToError("[INTRUDER] clipboard copy failed: " + ex.getMessage());
        }

        api.logging().logToOutput("[INTRUDER] opened with " + parsed.offsets.size()
                + " position(s); " + payloadsCopied + " payload(s) copied to clipboard.");
        flashButton(btn, "Opened — payloads copied!", "Send to Intruder");

        // Custom dialog with an explicit 'Copy payloads to clipboard' button so
        // the operator can re-copy the payloads if the automatic copy got
        // clobbered (common: they switched to another window and copied
        // something else in the meantime).
        final String payloadsForClipboard = payloadsBlock;
        Object[] options = {"Copy payloads to clipboard", "OK"};
        int choice = JOptionPane.showOptionDialog(this,
                "Intruder opened with " + parsed.offsets.size() + " §-marked position(s).\n\n"
              + payloadsCopied + " payload(s) have been copied to the clipboard automatically.\n"
              + "Switch to Intruder → Payloads tab → Paste (or Load from clipboard).\n\n"
              + "If the clipboard was overwritten by another app while this ran, use the\n"
              + "'Copy payloads to clipboard' button below to put them back on the clipboard.",
                "XagentAI — Intruder ready",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                null,
                options,
                options[1]);                     // default = OK
        if (choice == 0) {                       // operator pressed Copy
            try {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(payloadsForClipboard), null);
                api.logging().logToOutput("[INTRUDER] payloads re-copied to clipboard on operator request ("
                        + payloadsForClipboard.length() + " chars).");
                flashButton(btn, "Payloads re-copied!", "Send to Intruder");
            } catch (Exception ex) {
                api.logging().logToError("[INTRUDER] manual clipboard re-copy failed: " + ex.getMessage());
                JOptionPane.showMessageDialog(this,
                        "Failed to copy payloads to the clipboard: " + ex.getMessage(),
                        "XagentAI — error", JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    /**
     * Walk the wire format, strip '§' markers and record each pair as a
     * byte-offset [start, end] couple. The caller (Intruder dispatcher)
     * turns the offsets into Montoya {@link Range} objects; keeping the
     * util layer free of {@code Range.range()} lets us unit-test it
     * outside Burp (the Montoya factory locator is null off-runtime).
     */
    static ParsedWire extractRangesFromMarkers(String wireWithMarkers) {
        if (wireWithMarkers == null) wireWithMarkers = "";
        StringBuilder clean = new StringBuilder();
        List<int[]> offsets = new ArrayList<>();
        Integer openByteOffset = null;
        for (int i = 0; i < wireWithMarkers.length(); i++) {
            char ch = wireWithMarkers.charAt(i);
            if (ch == '§') {
                int bytePos = clean.toString().getBytes(StandardCharsets.UTF_8).length;
                if (openByteOffset == null) {
                    openByteOffset = bytePos;
                } else {
                    offsets.add(new int[]{openByteOffset, bytePos});
                    openByteOffset = null;
                }
            } else {
                clean.append(ch);
            }
        }
        // If a marker was opened but never closed, drop it silently.
        byte[] cleanBytes = clean.toString().getBytes(StandardCharsets.UTF_8);
        return new ParsedWire(cleanBytes, offsets);
    }

    static final class ParsedWire {
        final byte[] contentBytes;
        final List<int[]> offsets;
        ParsedWire(byte[] c, List<int[]> o) { contentBytes = c; offsets = o; }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max);
    }

    private static void flashButton(JButton btn, String temp, String original) {
        btn.setText(temp);
        Timer t = new Timer(1800, ev -> btn.setText(original));
        t.setRepeats(false);
        t.start();
    }

    /** Render Markdown to a self-contained HTML string with inline styles. */
    private static String renderMarkdown(String md) {
        Parser parser = Parser.builder().build();
        HtmlRenderer renderer = HtmlRenderer.builder().build();
        String body = renderer.render(parser.parse(md == null ? "" : md));

        String css = ""
                + "body { font-family: -apple-system, 'Segoe UI', Arial, sans-serif; font-size: 12pt; color: #222; }"
                + "h1 { font-size: 16pt; margin: 14px 0 6px 0; }"
                + "h2 { font-size: 14pt; margin: 12px 0 6px 0; }"
                + "h3 { font-size: 13pt; margin: 10px 0 4px 0; }"
                + "p  { margin: 6px 0 6px 0; }"
                + "ul, ol { margin: 4px 0 8px 20px; }"
                + "li { margin: 2px 0; }"
                + "code { font-family: Menlo, Consolas, monospace; background-color: #F0F0F0; padding: 1px 4px; }"
                + "pre  { background-color: #F7F7F7; padding: 8px; }"
                + "pre code { background-color: transparent; padding: 0; }"
                + "strong { font-weight: bold; }"
                + "em { font-style: italic; }"
                + "blockquote { border-left: 3px solid #CCC; padding-left: 8px; color: #555; margin: 6px 0; }"
                + "hr { border: 0; border-top: 1px solid #DDD; margin: 10px 0; }"
                + "a { color: #0366D6; }";

        return "<html><head><style>" + css + "</style></head><body>" + body + "</body></html>";
    }

    private static String nullSafe(String s, String def) {
        return (s == null || s.isEmpty()) ? def : s;
    }
}
