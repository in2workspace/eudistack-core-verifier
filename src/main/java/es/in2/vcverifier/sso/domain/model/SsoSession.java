package es.in2.vcverifier.sso.domain.model;

import lombok.Data;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

@Data
public class SsoSession {

    private final SsoSessionId id;
    private final String tenant;
    private final String holderHash;

    private final Instant establishedAt;
    private final Instant expiresAt;

    // control de idle timeout
    private Instant lastUsedAt;

    private SsoSessionState state;

    private SsoSession(
            SsoSessionId id,
            String tenant,
            String holderHash,
            Instant establishedAt,
            Instant expiresAt,
            Instant lastUsedAt,
            SsoSessionState state
    ) {
        this.id = id;
        this.tenant = tenant;
        this.holderHash = holderHash;
        this.establishedAt = establishedAt;
        this.expiresAt = expiresAt;
        this.lastUsedAt = lastUsedAt;
        this.state = state;

        validateInvariants();
    }

    /**
     * Construye una nueva sesión.
     */
    public static SsoSession establish(String tenant, String holderHash, Duration ttl) {

        Objects.requireNonNull(tenant, "tenant cannot be null");
        Objects.requireNonNull(holderHash, "holderHash cannot be null");
        Objects.requireNonNull(ttl, "ttl cannot be null");

        Instant now = Instant.now();

        return new SsoSession(
                SsoSessionId.generate(),
                tenant,
                holderHash,
                now,
                now.plus(ttl),
                now, // lastUsedAt inicial = creación
                SsoSessionState.ACTIVE
        );
    }

    /**
     * Reemplaza una sesión activa.
     */
    public void supersede() {

        if (isExpired()) {
            throw new IllegalStateException("Cannot supersede an expired session");
        }

        if (state == SsoSessionState.TERMINATED) {
            throw new IllegalStateException("Session already terminated");
        }

        this.state = SsoSessionState.SUPERSEDED;
    }

    // =========================
    // BUSINESS RULES
    // =========================

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * Regla combinada de validez SSO:
     * - no expirado por tiempo absoluto
     * - no excedido idle TTL
     */
    public boolean isValid(Instant now, Duration idleTtl) {

        if (idleTtl == null) {
            throw new IllegalArgumentException("idleTtl cannot be null");
        }

        boolean notExpired = now.isBefore(expiresAt);

        boolean idleValid = lastUsedAt != null &&
                Duration.between(lastUsedAt, now).compareTo(idleTtl) <= 0;

        return notExpired && idleValid;
    }

    public boolean belongsToTenant(String tenant) {
        return this.tenant.equals(tenant);
    }

    /**
     * Actualiza el último uso (idle tracking)
     */
    public void touch(Instant now) {
        this.lastUsedAt = now;
    }

    // =========================
    // INVARIANT VALIDATION
    // =========================

    private void validateInvariants() {

        if (tenant == null || tenant.isBlank()) {
            throw new IllegalArgumentException("Tenant must not be null/blank");
        }

        if (holderHash == null || holderHash.isBlank()) {
            throw new IllegalArgumentException("HolderHash must not be null/blank");
        }

        if (expiresAt.isBefore(establishedAt)) {
            throw new IllegalStateException("expiresAt cannot be before establishedAt");
        }

        if (Instant.now().isAfter(expiresAt)) {
            throw new IllegalStateException("Session cannot be created already expired");
        }

        if (lastUsedAt == null) {
            throw new IllegalStateException("lastUsedAt must be initialized");
        }
    }
}
