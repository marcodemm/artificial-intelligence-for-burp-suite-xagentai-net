package net.xagentai.burp.ai.providers;

/** Result of a connection test from the Settings panel. */
public record TestResult(boolean ok, String message, long latencyMillis) {

    public static TestResult ok(String message, long latencyMillis) {
        return new TestResult(true, message, latencyMillis);
    }

    public static TestResult fail(String message) {
        return new TestResult(false, message, -1L);
    }
}
