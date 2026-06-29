package es.in2.vcverifier.sso.domain.model;


import lombok.Data;
import java.time.Instant;
import java.time.Duration;
import java.util.Objects;

@Data
public class SsoSession {

    private final SsoSessionId id;
    private final String tenant;
    private final String holderHash;
    private final Instant establishedAt;
    private final Instant expiresAt;
    private SsoSessionState state;


    private SsoSession(
            SsoSessionId id,
            String tenant,
            String holderHash,
            Instant establishedAt,
            Instant expiresAt,
            SsoSessionState state
    ) {
        this.id = id;
        this.tenant = tenant;
        this.holderHash = holderHash;
        this.establishedAt = establishedAt;
        this.expiresAt = expiresAt;
        this.state = state;

        validateInvariants();
    }


    /**
     * Construye una nueva sesión.
     *
     * @param tenant
     * @param holderHash
     * @param ttl
     * @return
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
                SsoSessionState.ACTIVE
        );
    }


    /**
     * Reemplaza una sesión.
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

    public boolean belongsToTenant(String tenant) {
        return this.tenant.equals(tenant);
    }

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

        // Invariante: no puede crearse expirada
        if (Instant.now().isAfter(expiresAt)) {
            throw new IllegalStateException("Session cannot be created already expired");
        }
    }


}
