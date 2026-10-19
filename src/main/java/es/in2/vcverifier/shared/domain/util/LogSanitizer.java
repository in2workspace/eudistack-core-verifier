package es.in2.vcverifier.shared.domain.util;

/**
 * Strips CR/LF/TAB from a value before it is written to a log line, and caps its length, so a
 * crafted user-controlled value cannot forge additional log lines or entries (CWE-117 log
 * injection). Uses literal char replacement (rather than a regex character class) since that is
 * the form CodeQL's log-injection sanitizer barrier recognizes.
 */
public final class LogSanitizer {

    private static final int MAX_LOGGED_LENGTH = 64;
    private static final int MAX_CAUSE_DEPTH = 32;

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

    /**
     * Simple class name of the deepest cause of {@code throwable} (itself when it has no cause),
     * never a message: for WARN/ERROR lines where an exception message — e.g. a JDBC driver's SQL
     * or constraint detail — could carry data that must not be logged.
     */
    public static String rootCauseName(Throwable throwable) {
        if (throwable == null) {
            return null;
        }
        Throwable root = throwable;
        // Bounded walk: a cause chain may (in broken code) be cyclic.
        for (int depth = 0; depth < MAX_CAUSE_DEPTH && root.getCause() != null && root.getCause() != root; depth++) {
            root = root.getCause();
        }
        return root.getClass().getSimpleName();
    }
}
