package net.xagentai.burp.ai.providers;

/** Any failure talking to an AI provider (HTTP, auth, quota, parsing). */
public class AIException extends Exception {
    public AIException(String message) {
        super(message);
    }
    public AIException(String message, Throwable cause) {
        super(message, cause);
    }
}
