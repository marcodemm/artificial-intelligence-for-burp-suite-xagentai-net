package net.xagentai.burp.ai.ui;

import burp.api.montoya.MontoyaApi;

import net.xagentai.burp.ai.ExtensionLifecycle;
import net.xagentai.burp.ai.util.ActiveWafProber;
import net.xagentai.burp.ai.util.WafSignatures;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.KeyStroke;
import javax.swing.Timer;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;

import javax.swing.JComponent;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

/**
 * Modeless dialog that shows the outcome of an {@link ActiveWafProber}
 * run: baseline status, blind-match candidates with confidence, passive
 * (regex) matches picked up along the way, hardness summary, and the
 * per-payload table.
 *
 * <p>Footer buttons:
 * <ul>
 *   <li><b>Copy summary to clipboard</b> — markdown-friendly recap.</li>
 *   <li><b>Run WAF Bypass with AI</b> — hands the top detected WAF to the
 *       existing {@code onWafBypassHttp} flow as a seed hint via the
 *       {@code onBypassWithHint} callback supplied by the caller.</li>
 *   <li><b>Close</b></li>
 * </ul>
 */
public final class ActiveWafResultDialog extends JDialog {

    private final String rawMarkdown;

    public ActiveWafResultDialog(MontoyaApi api,
                                 ActiveWafProber.ProbeResult result,
                                 String targetUrl,
                                 Runnable onBypassWithHint) {
        setTitle("XagentAI — Active WAF Detection (" + hostOf(targetUrl) + ")");
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setModal(false);
        setPreferredSize(new Dimension(880, 640));
        setLayout(new BorderLayout(10, 10));

        LinkedHashMap<String, Integer> matches = safeMatchBlind(result);
        this.rawMarkdown = buildMarkdown(result, targetUrl, matches);

        // --- Header (gray, muted) ----------------------------------------
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        String info = "Baseline HTTP " + result.baselineStatus
                + "   ·   Blocked " + result.blockedCount() + "/" + result.blocked.length
                + "   ·   Hardness: " + result.hardnessLabel() + " (" + result.hardnessPct() + "%)"
                + "   ·   Requests: " + result.totalRequests
                + (result.cancelled ? "   ·   CANCELLED" : "");
        JLabel infoLabel = new JLabel(info);
        infoLabel.setForeground(new Color(0x808080));
        header.add(infoLabel);
        add(header, BorderLayout.NORTH);

        // --- Body: Markdown rendered as HTML -----------------------------
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

        // --- Footer -------------------------------------------------------
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));

        if (onBypassWithHint != null && !matches.isEmpty()) {
            JButton bypass = new JButton("Run WAF Bypass with AI");
            String top = matches.keySet().iterator().next();
            bypass.setToolTipText("Open the WAF Bypass with AI flow using '"
                    + top + "' as the detected-WAF hint.");
            bypass.addActionListener(e -> onBypassWithHint.run());
            footer.add(bypass);
        }

        JButton copyBtn = new JButton("Copy summary to clipboard");
        copyBtn.setToolTipText("Copy the Markdown summary to the clipboard.");
        copyBtn.addActionListener(e -> {
            try {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(rawMarkdown), null);
                flashButton(copyBtn, "Copied!", "Copy summary to clipboard");
            } catch (RuntimeException ex) {
                flashButton(copyBtn, "Copy failed", "Copy summary to clipboard");
            }
        });
        footer.add(copyBtn);

        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        footer.add(closeBtn);
        add(footer, BorderLayout.SOUTH);

        getRootPane().registerKeyboardAction(
                e -> dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        getRootPane().setDefaultButton(closeBtn);

        pack();
        setLocationRelativeTo(ExtensionLifecycle.suiteFrame());
    }

    private static LinkedHashMap<String, Integer> safeMatchBlind(
            ActiveWafProber.ProbeResult result) {
        try {
            if (!result.baselineOk || result.blocked.length == 0) {
                return new LinkedHashMap<>();
            }
            return WafSignatures.get().matchBlind(result.blocked);
        } catch (RuntimeException ex) {
            return new LinkedHashMap<>();
        }
    }

    private static String buildMarkdown(ActiveWafProber.ProbeResult result,
                                        String targetUrl,
                                        LinkedHashMap<String, Integer> matches) {
        StringBuilder md = new StringBuilder();
        md.append("# Active WAF Detection\n\n");
        md.append("**Target:** `").append(targetUrl == null ? "?" : targetUrl).append("`  \n");
        if (!result.baselineOk) {
            md.append("**Baseline:** *failed — could not establish a baseline response.*\n\n");
        } else {
            md.append("**Baseline:** HTTP ").append(result.baselineStatus)
              .append(" (").append(result.baselineBodyLen).append(" bytes)");
            if (!result.baselineReliable) {
                md.append(" — ⚠️ *unreliable*");
            }
            md.append("  \n");
        }
        // Probes = total requests minus the 2 baselines (or 1 if the second
        // baseline couldn't be sent because the scan was cancelled early).
        int probesSent = Math.max(0, result.totalRequests - (result.baselineOk ? 2 : 1));
        md.append("**Probes sent:** ").append(probesSent)
          .append(" / ").append(result.blocked.length)
          .append(" payload(s)  \n");
        md.append("**Blocked:** ").append(result.blockedCount())
          .append(" / ").append(result.blocked.length)
          .append(" (hardness: **").append(result.hardnessLabel())
          .append("**, ").append(result.hardnessPct()).append("%)  \n");
        md.append("**Blocked categories:** ")
          .append(ActiveWafProber.categorySummary(result.details)).append("\n");

        if (!result.baselineReliable && result.baselineOk) {
            md.append("\n> ⚠️ **Baseline is unreliable.** ");
            if (result.baselineStatus >= 400) {
                md.append("The endpoint returned HTTP ").append(result.baselineStatus)
                  .append(" to a benign request (likely an auth challenge, a validation ")
                  .append("error or a maintenance page). The prober switched to a stricter ")
                  .append("rule for this run — a payload is only counted as *blocked* when ")
                  .append("it triggers an explicit block status (403/406/429/451/503) **or** ")
                  .append("a protection keyword. Blind-match confidence should still be ")
                  .append("treated as a hint, not a verdict.\n");
            } else {
                md.append("The two baseline requests returned different status codes — the ")
                  .append("endpoint is non-deterministic, so the blocked-vector may contain ")
                  .append("noise. Consider re-running against a stable URL.\n");
            }
        }

        if (result.cancelled) {
            md.append("\n> ⚠️ **Scan cancelled by operator** — results are partial.\n");
        }

        // --- Blind matches ---
        md.append("\n## Blind match (identYwaf algorithm)\n\n");
        if (matches.isEmpty()) {
            md.append("_No WAF matched the observed block pattern._\n");
            md.append("Possible reasons: no WAF in front, WAF did not block any probe, "
                    + "or the signature does not appear in the identYwaf catalog yet.\n");
        } else {
            md.append("| WAF | Confidence |\n|---|---|\n");
            int shown = 0;
            for (Map.Entry<String, Integer> e : matches.entrySet()) {
                md.append("| ").append(e.getKey()).append(" | ")
                  .append(e.getValue()).append("% |\n");
                if (++shown >= 10) break;
            }
            if (matches.size() > 10) {
                md.append("\n_…and ").append(matches.size() - 10).append(" more._\n");
            }
        }

        // --- Passive matches ---
        md.append("\n## Passive match (regex over any response)\n\n");
        if (result.passiveMatches.isEmpty()) {
            md.append("_No passive regex hit on any of the responses seen._\n");
        } else {
            for (String p : result.passiveMatches) {
                md.append("- ").append(p).append("\n");
            }
        }

        // --- Signature ---
        try {
            if (result.baselineOk && result.blocked.length > 0) {
                md.append("\n## Signature\n\n```\n")
                  .append(WafSignatures.get().computeSignature(result.blocked))
                  .append("\n```\n");
            }
        } catch (RuntimeException ignored) {}

        // --- Per-payload table ---
        md.append("\n## Per-payload results\n\n");
        md.append("| # | Category | Status | Blocked | Payload | Why |\n");
        md.append("|---:|---|---:|:---:|---|---|\n");
        for (ActiveWafProber.ProbeDetail d : result.details) {
            md.append("| ").append(d.payloadIndex + 1)
              .append(" | ").append(escapeMd(d.category))
              .append(" | ").append(d.statusCode < 0 ? "-" : String.valueOf(d.statusCode))
              .append(" | ").append(d.blocked ? "✅" : "·")
              .append(" | `").append(escapeMd(truncate(d.payload, 60))).append("`")
              .append(" | ").append(escapeMd(d.reason))
              .append(" |\n");
        }

        md.append("\n---\n")
          .append("_Blind inference logic ported from "
                  + "[identYwaf](https://github.com/stamparm/identYwaf) "
                  + "(MIT, Copyright 2019-2026 Miroslav Stampar). "
                  + "See `NOTICE-identywaf.txt` in the extension JAR for the full notice._\n");
        return md.toString();
    }

    // --- Rendering / helpers ---------------------------------------------

    private static String renderMarkdown(String md) {
        Parser parser = Parser.builder().build();
        HtmlRenderer renderer = HtmlRenderer.builder().build();
        String body = renderer.render(parser.parse(md == null ? "" : md));
        String css = ""
                + "body { font-family: -apple-system, 'Segoe UI', Arial, sans-serif; font-size: 12pt; color: #222; }"
                + "h1 { font-size: 16pt; margin: 14px 0 6px 0; }"
                + "h2 { font-size: 14pt; margin: 12px 0 6px 0; }"
                + "p  { margin: 6px 0; }"
                + "ul, ol { margin: 4px 0 8px 20px; }"
                + "li { margin: 2px 0; }"
                + "code { font-family: Menlo, Consolas, monospace; background-color: #F0F0F0; padding: 1px 4px; }"
                + "pre  { background-color: #F7F7F7; padding: 8px; }"
                + "pre code { background-color: transparent; padding: 0; }"
                + "table { border-collapse: collapse; margin: 6px 0; }"
                + "th, td { border: 1px solid #DDD; padding: 4px 8px; text-align: left; }"
                + "th { background-color: #F0F0F0; }"
                + "blockquote { border-left: 3px solid #CCC; padding-left: 8px; color: #555; }"
                + "hr { border: 0; border-top: 1px solid #DDD; margin: 10px 0; }"
                + "a { color: #0366D6; }";
        return "<html><head><style>" + css + "</style></head><body>" + body + "</body></html>";
    }

    private static String escapeMd(String s) {
        if (s == null) return "";
        return s.replace("|", "\\|").replace("\r", "").replace("\n", " ");
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    private static String hostOf(String url) {
        if (url == null) return "?";
        try {
            java.net.URI u = java.net.URI.create(url);
            return u.getHost() == null ? url : u.getHost();
        } catch (RuntimeException ex) {
            return url;
        }
    }

    private static void flashButton(JButton btn, String temp, String original) {
        btn.setText(temp);
        Timer t = new Timer(1800, ev -> btn.setText(original));
        t.setRepeats(false);
        t.start();
    }

    /** Bridge so XagentContextMenuProvider can hand the dialog a "run bypass with X" closure. */
    public interface OnBypassWithHint extends BiConsumer<String, String> {}
}
