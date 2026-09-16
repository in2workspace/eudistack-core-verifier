package es.in2.vcverifier.shared.domain.util;

/**
 * Strips CR/LF/TAB from a value before it is written to a log line, and caps its length, so a
 * crafted user-controlled value cannot forge additional log lines or entries (CWE-117 log
 * injection). Uses literal char replacement (rather than a regex character class) since that is
 * the form CodeQL's log-injection sanitizer barrier recognizes.
 */
public final class LogSanitizer {

    private static final int MAX_LOGGED_LENGTH = 64;

    private LogSanitizer() {
    }

    public static String sanitize(String value) {
        if (value == null) {
            return null;
        }
        String sanitized = value
                .replace('\r', '_')
                .replace('\n', '_')
                .replace('\t', '_');
        return sanitized.length() > MAX_LOGGED_LENGTH
                ? sanitized.substring(0, MAX_LOGGED_LENGTH) + "...(truncated)"
                : sanitized;
    }
}
