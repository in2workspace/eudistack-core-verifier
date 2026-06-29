package es.in2.vcverifier.sso.domain.model;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * Value Object that represents the opaque identifier of an SsoSession.
 * AD-2: generated with SecureRandom (256-bit) encoded as base64url without padding.
 */
public final class SsoSessionId implements Serializable {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String value;

    private SsoSessionId(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("SsoSessionId cannot be null or blank");
        }
        this.value = value;
    }

    /** Generates a new session ID: 32 SecureRandom bytes encoded as base64url without padding (AD-2). */
    public static SsoSessionId generate() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return new SsoSessionId(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    /** Reconstitutes from persistence (DB, JSON, etc.). */
    public static SsoSessionId of(String value) {
        return new SsoSessionId(value);
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SsoSessionId that)) return false;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
