package es.in2.vcverifier.shared.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.turbo.TurboFilter;
import ch.qos.logback.core.spi.FilterReply;
import org.slf4j.Marker;

import java.util.List;

/**
 * Suppresses DEBUG-level log lines that mention noisy endpoints
 * (health checks, well-known discovery) to reduce log noise in development.
 */
public class SuppressEndpointLogFilter extends TurboFilter {

    private static final List<String> SUPPRESSED_PATHS = List.of(
            "/health",
            "/.well-known/openid-configuration"
    );

    @Override
    public FilterReply decide(Marker marker, Logger logger, Level level,
                              String format, Object[] params, Throwable t) {
        if (level == null || !level.isGreaterOrEqual(Level.DEBUG) || level.isGreaterOrEqual(Level.INFO)) {
            return FilterReply.NEUTRAL;
        }
        if (format != null) {
            for (String path : SUPPRESSED_PATHS) {
                if (format.contains(path)) {
                    return FilterReply.DENY;
                }
            }
        }
        return FilterReply.NEUTRAL;
    }
}