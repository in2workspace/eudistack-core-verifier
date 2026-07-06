package es.in2.vcverifier.shared.domain.util;

import java.net.URI;
import java.util.Locale;

/**
 * Normalizes URI origins (scheme + host + port) for comparison purposes.
 * Scheme and host are case-insensitive per RFC 3986 3.1/3.2.2, so comparing raw
 * strings rejects otherwise-identical origins that differ only in case or in an
 * explicit vs. implicit default port.
 */
public final class OriginNormalizer {

    private OriginNormalizer() {
    }

    /**
     * Returns the normalized {@code scheme://host[:port]} origin of the given URI,
     * or {@code null} if the URI is malformed or has no scheme/host.
     */
    public static String normalizeOrigin(String uri) {
        URI parsed = parse(uri);
        if (parsed == null) {
            return null;
        }
        String normalizedScheme = parsed.getScheme().toLowerCase(Locale.ROOT);
        String normalizedHost = parsed.getHost().toLowerCase(Locale.ROOT);
        return normalizedScheme + "://" + normalizedHost + portSuffix(normalizedScheme, parsed.getPort());
    }

    /**
     * Returns the given URI with its scheme and host normalized (lower-cased, default
     * port dropped), leaving path/query/fragment untouched — those remain
     * case-sensitive and must match exactly for redirect_uri comparisons.
     * Returns {@code null} if the URI is malformed or has no scheme/host.
     */
    public static String normalizeUri(String uri) {
        URI parsed = parse(uri);
        if (parsed == null) {
            return null;
        }
        String normalizedScheme = parsed.getScheme().toLowerCase(Locale.ROOT);
        String normalizedHost = parsed.getHost().toLowerCase(Locale.ROOT);

        StringBuilder sb = new StringBuilder();
        sb.append(normalizedScheme).append("://");
        if (parsed.getRawUserInfo() != null) {
            sb.append(parsed.getRawUserInfo()).append('@');
        }
        sb.append(normalizedHost).append(portSuffix(normalizedScheme, parsed.getPort()));
        if (parsed.getRawPath() != null) {
            sb.append(parsed.getRawPath());
        }
        if (parsed.getRawQuery() != null) {
            sb.append('?').append(parsed.getRawQuery());
        }
        if (parsed.getRawFragment() != null) {
            sb.append('#').append(parsed.getRawFragment());
        }
        return sb.toString();
    }

    private static URI parse(String uri) {
        if (uri == null || uri.isBlank()) {
            return null;
        }
        try {
            URI parsed = URI.create(uri);
            if (parsed.getScheme() == null || parsed.getHost() == null) {
                return null;
            }
            return parsed;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String portSuffix(String normalizedScheme, int port) {
        boolean defaultPort = port == -1
                || ("https".equals(normalizedScheme) && port == 443)
                || ("http".equals(normalizedScheme) && port == 80);
        return defaultPort ? "" : ":" + port;
    }
}
