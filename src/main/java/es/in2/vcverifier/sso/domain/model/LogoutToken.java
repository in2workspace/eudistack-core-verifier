package es.in2.vcverifier.sso.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Value object que modela los claims del {@code logout_token} de un Single Logout (US-06),
 * conforme a OIDC Back-Channel Logout 1.0 §2.4.
 * <p>
 * Inmutable y sin lógica de firma: la firma ES256 la aplica el adapter de infraestructura
 * ({@code LogoutTokenFactory}). No incluye {@code nonce} (prohibido explícitamente por la spec §2.4).
 */
public record LogoutToken(
        String iss,
        String aud,
        String sid,
        Instant iat,
        String jti
) {

    /** OIDC Back-Channel Logout 1.0 §2.4: claim {@code events} fijo, no configurable por el llamante. */
    private static final String BACKCHANNEL_LOGOUT_EVENT_URI =
            "http://schemas.openid.net/event/backchannel-logout";

    /**
     * [W3]: ventana de validez del {@code logout_token}, acotada para limitar la superficie de
     * replay contra el endpoint back-channel del RP (la spec no exige {@code exp}, pero tampoco
     * lo prohíbe — un token de un solo uso con vida corta es más seguro que uno sin expiración).
     */
    private static final Duration EXPIRATION_WINDOW = Duration.ofMinutes(2);

    public LogoutToken {
        Objects.requireNonNull(iss, "iss cannot be null");
        Objects.requireNonNull(aud, "aud cannot be null");
        Objects.requireNonNull(sid, "sid cannot be null");
        Objects.requireNonNull(iat, "iat cannot be null");
        Objects.requireNonNull(jti, "jti cannot be null");
    }

    public static LogoutToken of(String iss, String aud, String sid, Instant iat, String jti) {
        return new LogoutToken(iss, aud, sid, iat, jti);
    }

    /**
     * Claim {@code events} fijo por spec (OIDC Back-Channel Logout 1.0 §2.4): no es un dato de negocio
     * configurable, por lo que no forma parte de los componentes del record.
     */
    public Map<String, Object> events() {
        return Map.of(BACKCHANNEL_LOGOUT_EVENT_URI, Map.of());
    }

    /** [W3]: {@code exp} derivado de {@code iat + 2min} — no es un componente independiente del record. */
    public Instant exp() {
        return iat.plus(EXPIRATION_WINDOW);
    }
}