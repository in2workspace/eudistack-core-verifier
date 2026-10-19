package es.in2.vcverifier.shared.domain.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builds the authorization response sent to a client's (already validated) {@code redirect_uri}:
 * success (RFC 6749 §4.1.2) or error (RFC 6749 §4.1.2.1 / OIDC Core 1.0 §3.1.2.6).
 *
 * <p>Parameters are added to the query of the registered {@code redirect_uri}, keeping the query it
 * may already have (RFC 6749 §3.1.2), and form-encoded (RFC 6749 Appendix B). Every response carries
 * {@code iss} (RFC 9207 §2): the issuer the discovery document advertises for the host the client
 * used at {@code /oidc/authorize}, so the client can detect a mix-up between authorization servers.
 *
 * <p>A {@code redirect_uri} that is not a valid, ASCII-only, hierarchical URI reference (e.g. with an
 * unencoded space, '{' or '|') cannot carry a response: the builders throw
 * {@link IllegalArgumentException}.
 *
 * <p>JDK only (domain package). Output normalisation, identical to the former
 * {@code UriComponentsBuilder}-based version: scheme lower-cased, empty port and empty path segments
 * dropped, client query re-serialized with values grouped by name, empty fragment dropped.
 */
public final class AuthorizationResponseUri {

    private static final String CODE = "code";
    private static final String STATE = "state";
    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPTION = "error_description";
    private static final String ISS = "iss";

    /** name, optional '=', optional value; empty segments ({@code &&}) carry no parameter. */
    private static final Pattern QUERY_PARAM = Pattern.compile("([^&=]+)(=?)([^&]+)?");
    private static final Pattern EMPTY_PATH_SEGMENTS = Pattern.compile("/{2,}");

    private AuthorizationResponseUri() {
    }

    public static String success(String redirectUri, String code, String state, String issuer) {
        Response response = Response.to(redirectUri);
        response.addParam(CODE, code);
        response.addParam(STATE, state);
        response.addParam(ISS, issuer);
        return response.toUriString();
    }

    /**
     * @param errorDescription short, stable, human-readable text — never request input echoed back
     */
    public static String error(String redirectUri, String error, String errorDescription, String state,
                               String issuer) {
        Response response = Response.to(redirectUri);
        response.addParam(ERROR, error);
        response.addParam(ERROR_DESCRIPTION, errorDescription);
        response.addParam(STATE, state);
        response.addParam(ISS, issuer);
        return response.toUriString();
    }

    /**
     * The {@code redirect_uri} split into scheme + authority + path, its query parameters (grouped
     * by name in first-seen order; a {@code null} value is a bare name) and its fragment.
     */
    private static final class Response {

        private final String base;
        private final Map<String, List<String>> queryParams = new LinkedHashMap<>();
        private final String fragment;

        private Response(String base, String rawQuery, String fragment) {
            this.base = base;
            this.fragment = fragment;
            if (rawQuery != null) {
                Matcher matcher = QUERY_PARAM.matcher(rawQuery);
                while (matcher.find()) {
                    String value = matcher.group(3);
                    put(matcher.group(1), value != null ? value : (matcher.group(2).isEmpty() ? null : ""));
                }
            }
        }

        static Response to(String redirectUri) {
            if (redirectUri == null) {
                throw new IllegalArgumentException("redirect_uri is required");
            }
            URI parsed;
            try {
                parsed = new URI(redirectUri);
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("redirect_uri is not a valid URI", e);
            }
            if (!StandardCharsets.US_ASCII.newEncoder().canEncode(redirectUri)) {
                throw new IllegalArgumentException("redirect_uri contains non-ASCII characters");
            }
            if (parsed.isOpaque()) {
                throw new IllegalArgumentException("redirect_uri is not a hierarchical URI");
            }
            String path = parsed.getRawPath();
            String query = parsed.getRawQuery();
            String fragment = parsed.getRawFragment();
            // RFC 3986 §3.2.2: '[' and ']' are only allowed around an IP literal host.
            if (containsBracket(path) || containsBracket(query) || containsBracket(fragment)) {
                throw new IllegalArgumentException("redirect_uri contains '[' or ']' outside the host");
            }
            return new Response(base(parsed, path), query, fragment == null || fragment.isEmpty() ? null : fragment);
        }

        /** scheme (lower-cased), authority (without an empty port) and path (without empty segments). */
        private static String base(URI parsed, String path) {
            StringBuilder base = new StringBuilder();
            if (parsed.getScheme() != null) {
                base.append(parsed.getScheme().toLowerCase(Locale.ROOT)).append(':');
            }
            String authority = parsed.getRawAuthority();
            if (authority != null) {
                if (parsed.getPort() == -1 && authority.endsWith(":")) {
                    authority = authority.substring(0, authority.length() - 1);
                }
                base.append("//").append(authority);
            }
            return base.append(EMPTY_PATH_SEGMENTS.matcher(path).replaceAll("/")).toString();
        }

        private static boolean containsBracket(String component) {
            return component != null && (component.indexOf('[') >= 0 || component.indexOf(']') >= 0);
        }

        /** Absent or blank values are omitted (e.g. no {@code state} in the request). */
        void addParam(String name, String value) {
            if (value != null && !value.isBlank()) {
                put(name, URLEncoder.encode(value, StandardCharsets.UTF_8));
            }
        }

        private void put(String name, String value) {
            queryParams.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
        }

        String toUriString() {
            StringBuilder uri = new StringBuilder(base);
            StringJoiner query = new StringJoiner("&");
            queryParams.forEach((name, values) -> values.forEach(
                    value -> query.add(value != null ? name + "=" + value : name)));
            if (query.length() > 0) {
                uri.append('?').append(query);
            }
            if (fragment != null) {
                uri.append('#').append(fragment);
            }
            return uri.toString();
        }
    }
}
