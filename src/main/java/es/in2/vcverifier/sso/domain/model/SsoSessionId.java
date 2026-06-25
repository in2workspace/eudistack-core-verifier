package es.in2.vcverifier.sso.domain.model;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value Object que representa el identificador opaco de SsoSession.
 * AD-2: 256 bits de entropía, base64url sin padding (43 chars).
 */
public final class SsoSessionId implements Serializable {

    // base64url charset: A-Z a-z 0-9 - _
    private static final Pattern BASE64URL_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+$");
    private static final int EXPECTED_BYTE_LENGTH = 32; // 256 bits
    private static final int EXPECTED_STRING_LENGTH = 43; // ceil(32 * 4 / 3)

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String value;

    private SsoSessionId(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("SsoSessionId cannot be null or blank");
        }
        this.value = value;
    }

    // =========================
    // FACTORY METHODS
    // =========================

    /** Genera un nuevo ID con 256 bits de entropía (AD-2). */
    public static SsoSessionId generate() {
        byte[] bytes = new byte[EXPECTED_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(bytes);
        return new SsoSessionId(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    /** Reconstrucción desde persistencia. */
    public static SsoSessionId of(String value) {
        if (value == null || value.length() != EXPECTED_STRING_LENGTH || !BASE64URL_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException("Invalid SsoSessionId format: " + value);
        }
        return new SsoSessionId(value);
    }

    // =========================
    // GETTER
    // =========================
    public String getValue() {
        return value;
    }

    // =========================
    // VALUE SEMANTICS
    // =========================
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