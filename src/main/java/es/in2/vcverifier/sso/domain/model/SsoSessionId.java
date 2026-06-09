package es.in2.vcverifier.sso.domain.model;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

/**
 * Value Object que representa el identificador opaco de SsoSession
 */
public final class SsoSessionId implements Serializable {

    private final UUID value;

    // =========================
    // CONSTRUCTOR PRIVADO
    // =========================
    private SsoSessionId(UUID value) {
        if (value == null) {
            throw new IllegalArgumentException("SsoSessionId cannot be null");
        }
        this.value = value;
    }

    // =========================
    // FACTORY METHODS
    // =========================

    /**
     * Genera un nuevo ID (caso creación de aggregate)
     */
    public static SsoSessionId generate() {
        return new SsoSessionId(UUID.randomUUID());
    }

    /**
     * Reconstrucción desde persistencia (DB, JSON, etc.)
     */
    public static SsoSessionId of(UUID value) {
        return new SsoSessionId(value);
    }

    /**
     * Si te viene como String (por ejemplo de API o DB legacy)
     */
    public static SsoSessionId of(String value) {
        try {
            return new SsoSessionId(UUID.fromString(value));
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid SsoSessionId format: " + value, e);
        }
    }

    // =========================
    // GETTER
    // =========================
    public UUID getValue() {
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
        return value.toString();
    }
}