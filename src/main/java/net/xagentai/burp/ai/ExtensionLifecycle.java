package net.xagentai.burp.ai;

import burp.api.montoya.MontoyaApi;

import javax.swing.SwingUtilities;

import java.awt.Frame;
import java.awt.Window;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Process-wide registry of resources this extension spawns, so that
 * {@link burp.api.montoya.extension.ExtensionUnloadingHandler#extensionUnloaded()}
 * can tear them down cleanly (BApp Store acceptance criterion 6).
 *
 * Also caches {@link burp.api.montoya.ui.swing.SwingUtils#suiteFrame()} as the
 * parent to use for every top-level popup or dialog the extension creates
 * (criterion 10).
 */
public final class ExtensionLifecycle {

    private static final Set<Thread> threads = ConcurrentHashMap.newKeySet();
    private static final Set<Window> windows = ConcurrentHashMap.newKeySet();
    private static volatile Frame suiteFrame;

    private ExtensionLifecycle() {}

    /** Called once from {@code initialize()} so we remember the parent frame. */
    public static void setSuiteFrame(Frame f) {
        suiteFrame = f;
    }

    /** Parent for every popup / dialog the extension creates. May be null on very early calls. */
    public static Frame suiteFrame() {
        return suiteFrame;
    }

    /**
     * Launch a daemon background thread that is auto-interrupted on extension
     * unload. The task is wrapped so uncaught exceptions reach Burp's extension
     * error stream instead of being silently swallowed (criterion 5).
     */
    public static Thread startTracked(MontoyaApi api, Runnable task, String name) {
        Thread t = new Thread(() -> {
            try {
                task.run();
            } catch (Throwable ex) {
                api.logging().logToError("[" + name + "] uncaught " + ex.getClass().getSimpleName()
                        + ": " + ex.getMessage());
                for (StackTraceElement ste : ex.getStackTrace()) {
                    api.logging().logToError("    at " + ste);
                }
            } finally {
                threads.remove(Thread.currentThread());
            }
        }, name);
        t.setDaemon(true);
        threads.add(t);
        t.start();
        return t;
    }

    /** Register a top-level window so it gets disposed on extension unload. */
    public static void trackWindow(Window w) {
        if (w == null) return;
        windows.add(w);
    }

    /** Called from {@link burp.api.montoya.extension.ExtensionUnloadingHandler#extensionUnloaded()}. */
    public static void shutdown(MontoyaApi api) {
        api.logging().logToOutput("XagentAI unloading: interrupting " + threads.size()
                + " background thread(s), closing " + windows.size() + " window(s)...");
        for (Thread t : threads) {
            if (t.isAlive()) t.interrupt();
        }
        threads.clear();
        SwingUtilities.invokeLater(() -> {
            for (Window w : windows) {
                try { w.dispose(); } catch (Exception ignored) {}
            }
            windows.clear();
        });
    }
}
