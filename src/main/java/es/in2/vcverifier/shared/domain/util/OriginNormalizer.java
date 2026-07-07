package es.in2.vcverifier.shared.domain.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;


public final class OriginNormalizer {

    private static final Map<String, Integer> DEFAULT_PORTS = Map.of("http", 80, "https", 443);

    private OriginNormalizer() {
    }

    /**
     * Parses the given URI and returns its normalized {@code scheme://host[:port]}
     * origin, or {@code null} if it is malformed or has no scheme/host.
     */
    public static URI normalize(String uri) {
        return parseUri(uri).map(OriginNormalizer::normalize).orElse(null);
    }

    /**
     * Returns the normalized {@code scheme://host[:port]} origin of the given URI
     * (lower-cased scheme/host, default port dropped), or {@code null} if it has
     * no scheme/host.
     */
    public static URI normalize(URI uri) {
        if (uri == null || !hasOrigin(uri)) {
            return null;
        }
        SchemeHost schemeHost = normalizeSchemeHost(uri);
        int normalizedPort = normalizePort(schemeHost.scheme(), uri.getPort());
        try {
            return new URI(schemeHost.scheme(), null, schemeHost.host(), normalizedPort, null, null, null);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    public static String normalizeUri(String uri) {
        return parseUri(uri).map(OriginNormalizer::buildNormalizedUri).orElse(null);
    }

    private static String buildNormalizedUri(URI parsed) {
        SchemeHost schemeHost = normalizeSchemeHost(parsed);

        StringBuilder sb = new StringBuilder();
        sb.append(schemeHost.scheme()).append("://");
        if (parsed.getRawUserInfo() != null) {
            sb.append(parsed.getRawUserInfo()).append('@');
        }
        int normalizedPort = normalizePort(schemeHost.scheme(), parsed.getPort());
        sb.append(schemeHost.host()).append(portSuffix(normalizedPort));
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

    private static Optional<URI> parseUri(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        try {
            URI parsed = URI.create(value);
            return hasOrigin(parsed) ? Optional.of(parsed) : Optional.empty();
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static boolean hasOrigin(URI uri) {
        return uri.getScheme() != null && uri.getHost() != null;
    }

    private static SchemeHost normalizeSchemeHost(URI parsed) {
        return new SchemeHost(
                parsed.getScheme().toLowerCase(Locale.ROOT),
                parsed.getHost().toLowerCase(Locale.ROOT));
    }

    private static String portSuffix(int normalizedPort) {
        return normalizedPort == -1 ? "" : ":" + normalizedPort;
    }

    private static int normalizePort(String normalizedScheme, int port) {
        if (port == -1) {
            return -1;
        }
        Integer defaultPort = DEFAULT_PORTS.get(normalizedScheme);
        return Objects.equals(defaultPort, port) ? -1 : port;
    }

    private record SchemeHost(String scheme, String host) {
    }
}
