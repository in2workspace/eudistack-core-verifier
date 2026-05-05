package es.in2.vcverifier.shared.config;

import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;

import java.util.List;
import java.util.regex.Pattern;

public class MaskingPatternLayout extends PatternLayout {

    private static final String MASK = "***REDACTED***";
    private static final List<PatternReplacement> RULES = List.of(
            new PatternReplacement(
                    Pattern.compile("eyJ[A-Za-z0-9\\-_]+\\.eyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]*"),
                    MASK
            ),
            new PatternReplacement(
                    Pattern.compile("(?i)(Bearer\\s+)[A-Za-z0-9\\-_.~+/]+=*"),
                    "$1" + MASK
            ),
            new PatternReplacement(
                    Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,6}"),
                    MASK
            ),
            new PatternReplacement(
                    Pattern.compile(
                            "(?i)(\"?(?:tx_code|access_token|refresh_token|password|secret)\"?" +
                                    "\\s*[=:]\\s*\"?)[^\\s,&\"\\}\\]\\r\\n]+"),
                    "$1" + MASK
            )
    );

    @Override
    public String doLayout(ILoggingEvent event) {
        return applyMasking(super.doLayout(event));
    }

    // Internal helpers

    private static String applyMasking(String line) {
        if (line == null || line.isEmpty()) {
            return line;
        }
        String result = line;
        for (PatternReplacement rule : RULES) {
            result = rule.pattern().matcher(result).replaceAll(rule.replacement());
        }
        return result;
    }

    private record PatternReplacement(Pattern pattern, String replacement) {}
}

