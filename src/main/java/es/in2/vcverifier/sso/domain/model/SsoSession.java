package es.in2.vcverifier.sso.domain.model;

import lombok.Getter;
import lombok.ToString;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

@Getter
@ToString
public class SsoSession {

    private final SsoSessionId id;
    private final String tenant;
    private final String holderHash;

    private final Instant establishedAt;
    private final Instant expiresAt;

    // control de idle timeout
    private Instant lastUsedAt;

    private SsoSessionState state;

    // US-06: instante de terminación (Single Logout). Null hasta que terminate() transiciona la sesión.
    private Instant terminatedAt;

    // EUD-149 production-readiness: snapshot cifrado (AES-256-GCM) de las claims de la
    // credencial verificada en el establecimiento, persistido en la misma fila/transacción de
    // sso_session (sustituye la caché local no distribuida CacheStore<JsonNode>, que fallaba en
    // silencio cuando el establecimiento y la reutilización caían en réplicas distintas). W2
    // (review): un fallo al cifrar ya NO deja esto en null con la sesión igualmente persistida —
    // EstablishSsoSessionWorkflow.attachCredentialSnapshot falla cerrado (ni sesión ni cookie) si
    // no puede producir un snapshot. @ToString.Exclude: nunca volcar ciphertext crudo a logs.
    @ToString.Exclude
    private byte[] credentialSnapshotCiphertext;

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
                now,
                SsoSessionState.ACTIVE
        );
    }

    /**
     * Reconstruye una sesión desde persistencia. No valida que no haya expirado
     * (el repositorio filtra por estado; el workflow comprueba isValid()).
     */
    public static SsoSession reconstitute(
            SsoSessionId id,
            String tenant,
            String holderHash,
            Instant establishedAt,
            Instant expiresAt,
            Instant lastUsedAt,
            SsoSessionState state
    ) {
        return new SsoSession(id, tenant, holderHash, establishedAt, expiresAt, lastUsedAt, state);
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

    /**
     * Termina la sesión (US-06, Single Logout intra-tenant): transición {@code ACTIVE -> TERMINATED}.
     * Idempotente semánticamente (EC-01): invocar sobre un estado distinto de {@code ACTIVE} es
     * un no-op de dominio (no lanza, no muta {@code state}/{@code terminatedAt}). La idempotencia
     * real de persistencia (rows-affected) vive en {@code SsoSessionRepositoryPort#terminateActive}.
     */
    public void terminate(Instant now) {

        Objects.requireNonNull(now, "now cannot be null");

        if (state != SsoSessionState.ACTIVE) {
            return;
        }

        this.state = SsoSessionState.TERMINATED;
        this.terminatedAt = now;
    }

    // =========================
    // BUSINESS RULES
    // =========================

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * Criterio combinado de validez SSO:
     * {@code now < expiresAt  AND  now − lastUsedAt ≤ idleTtl}
     * <p>
     * {@code expiresAt} y {@code lastUsedAt} son invariantes del aggregate (introducidos en US-02):
     * {@code expiresAt} nunca es null ni anterior a {@code establishedAt};
     * {@code lastUsedAt} nunca es null (se inicializa en {@code establish()} y se actualiza con {@code touch()}).
     */
    public boolean isValid(Instant now, Duration idleTtl) {

        Objects.requireNonNull(now,     "now cannot be null");
        Objects.requireNonNull(idleTtl, "idleTtl cannot be null");

        boolean notExpired = now.isBefore(expiresAt);
        boolean idleValid  = Duration.between(lastUsedAt, now).compareTo(idleTtl) <= 0;

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

    /**
     * EUD-149: adjunta el snapshot cifrado de credencial antes de persistir (establecimiento) o
     * lo repuebla al reconstituir desde BD (lectura). {@code null} es un valor válido — sesiones
     * sin credencial que snapshotear, o previas a esta migración, simplemente no permiten
     * reutilización (fail-closed en {@code ReuseSsoSessionWorkflowImpl}).
     */
    public void attachCredentialSnapshot(byte[] ciphertext) {
        this.credentialSnapshotCiphertext = ciphertext;
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

        if (lastUsedAt == null) {
            throw new IllegalStateException("lastUsedAt must be initialized");
        }
    }
}
