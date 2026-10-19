package es.in2.vcverifier.shared.domain.util;

import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Builds the authorization response sent to a client's (already validated) {@code redirect_uri}:
 * success (RFC 6749 §4.1.2) or error (RFC 6749 §4.1.2.1 / OIDC Core 1.0 §3.1.2.6).
 *
 * <p>Parameters are added to the query of the registered {@code redirect_uri}, keeping the query it
 * may already have (RFC 6749 §3.1.2), and form-encoded (RFC 6749 Appendix B). Every response carries
 * {@code iss} (RFC 9207 §2): the issuer the discovery document advertises for the host the client
 * used at {@code /oidc/authorize}, so the client can detect a mix-up between authorization servers.
 */
public final class AuthorizationResponseUri {

    private static final String CODE = "code";
    private static final String STATE = "state";
    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPTION = "error_description";
    private static final String ISS = "iss";

    private AuthorizationResponseUri() {
    }

    public static String success(String redirectUri, String code, String state, String issuer) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri);
        addParam(builder, CODE, code);
        addParam(builder, STATE, state);
        addParam(builder, ISS, issuer);
        return builder.build(true).toUriString();
    }

    /**
     * @param errorDescription short, stable, human-readable text — never request input echoed back
     */
    public static String error(String redirectUri, String error, String errorDescription, String state,
                               String issuer) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri);
        addParam(builder, ERROR, error);
        addParam(builder, ERROR_DESCRIPTION, errorDescription);
        addParam(builder, STATE, state);
        addParam(builder, ISS, issuer);
        return builder.build(true).toUriString();
    }

    /** Absent or blank values are omitted (e.g. no {@code state} in the request). */
    private static void addParam(UriComponentsBuilder builder, String name, String value) {
        if (value != null && !value.isBlank()) {
            builder.queryParam(name, URLEncoder.encode(value, StandardCharsets.UTF_8));
        }
    }
}
