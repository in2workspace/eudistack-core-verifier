package es.in2.vcverifier.sso.infrastructure.persistence;

import es.in2.vcverifier.sso.domain.exception.SsoSessionRepositoryException;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionState;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

@Repository
@Slf4j
public class SsoSessionJdbcRepository implements SsoSessionRepositoryPort {

    private static final String TENANT_PATTERN = "^[a-z0-9-]{1,64}$";

    private final DataSource dataSource;
    private final Clock clock;

    private final int statementTimeoutMs = 5_000;

    private final int failureThreshold = 5;
    private final long openMillis = 60_000;
    private final AtomicInteger failureCounter = new AtomicInteger(0);
    private volatile long openUntil = 0L;

    public SsoSessionJdbcRepository(DataSource dataSource, Clock clock) {
        this.dataSource = dataSource;
        this.clock = clock;
    }

    // =========================================================
    // VALIDATION + CIRCUIT BREAKER
    // =========================================================

    private void ensureTenantSafe(String tenant) {
        if (tenant == null || !tenant.matches(TENANT_PATTERN)) {
            throw new IllegalArgumentException("Invalid tenant identifier: " + tenant);
        }
    }

    private void checkCircuit() {
        long now = System.currentTimeMillis();
        if (openUntil > now) {
            throw new IllegalStateException("SSO repository circuit is open until " + openUntil);
        }
    }

    private void recordSuccess() {
        failureCounter.set(0);
        openUntil = 0L;
    }

    private void recordFailure() {
        int f = failureCounter.incrementAndGet();
        if (f >= failureThreshold) {
            openUntil = System.currentTimeMillis() + openMillis;
            log.warn("SSO repository circuit opened for {} ms after {} consecutive failures", openMillis, f);
        }
    }

    /** NFR-S-547-02: never log session id or holder hash in full — 8-char prefix only. */
    // =========================================================
    private static String prefix8(String s) {
        // DB CONFIG
        if (s == null) return "null";
        // =========================================================
        return s.length() <= 8 ? s : s.substring(0, 8);
    }

    // =========================================================
    // DB CONFIG
    // =========================================================

    /**
     * Sets search_path to the quoted tenant schema + public.
     * Fail-closed: if this fails, we must NOT continue with unqualified SQL
     * as queries could hit the wrong schema (cross-tenant data leak risk).
     */
    private void setTenantSearchPath(Connection c, String tenant) throws SQLException {
        String sql = "SELECT set_config('search_path', ?, true)";
        try (PreparedStatement s = c.prepareStatement(sql)) {
            s.setString(1, "\"" + tenant + "\", public");
            s.execute();
        }
    }

    private void setStatementTimeout(Connection c) throws SQLException {
        String sql = "SELECT set_config('statement_timeout', ?, true)";
        try (PreparedStatement s = c.prepareStatement(sql)) {
            s.setString(1, String.valueOf(statementTimeoutMs));
            s.execute();
        }
    }

    // =========================================================
    // TENANT-SCOPED TRANSACTION
    // `set_config(..., true)` (is_local=true, search_path / statement_timeout) only persists
    // within an active transaction — a connection with autocommit=true reverts it before the
    // business statement runs, silently breaking schema-per-tenant isolation. Every method
    // below must run its business statement inside the same transaction as these calls.
    // Never pass is_local=false (the SET SESSION equivalent): with HikariCP that would leak
    // the setting into the pooled physical connection.
    // =========================================================

    @FunctionalInterface
    private interface SqlOperation<T> {
        T execute(Connection c) throws SQLException;
    }

    /**
     * Runs {@code op} inside a real transaction so `search_path` (when {@code tenant} is
     * given) and `statement_timeout` apply to the business statement. A {@code null} tenant
     * skips the search_path fix — used by {@link #findById} which intentionally queries
     * without a tenant filter (AC-04 cross-tenant detection).
     */
    private <T> T inTransaction(String tenant, SqlOperation<T> op) throws SQLException {
        try (Connection c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                if (tenant != null) {
                    setTenantSearchPath(c, tenant);
                }
                setStatementTimeout(c);
                T result = op.execute(c);
                c.commit();
                return result;
            } catch (SQLException e) {
                c.rollback();
                throw e;
            } finally {
                c.setAutoCommit(true);
            }
        }
    }

    // =========================================================
    // SAVE
    // =========================================================

    @Override
    public SsoSession save(SsoSession session) {
        ensureTenantSafe(session.getTenant());
        checkCircuit();

        String insertSql = """
            INSERT INTO sso_session
             (id, tenant, holder_hash, established_at, expires_at, last_used_at, state)
             VALUES (?, ?, ?, ?, ?, ?, ?)
        """;

        try {
            return inTransaction(session.getTenant(), c -> {
                try (PreparedStatement ps = c.prepareStatement(insertSql)) {
                    bindSession(ps, session);
                    ps.executeUpdate();
                    recordSuccess();
                    return session;
                } catch (SQLException e) {
                    if (!isUniqueViolation(e)) {
                        log.warn("Insert failed for session {}...: {}", prefix8(session.getId().getValue()), e.getMessage());
                        throw e;
                    }

                    log.info("Unique active session exists for tenant={} holderHash={}... - attempting supersede and retry",
                            session.getTenant(), prefix8(session.getHolderHash()));
                    supersedeActiveInConnection(c, session.getTenant(), session.getHolderHash());

                    try (PreparedStatement ps2 = c.prepareStatement(insertSql)) {
                        bindSession(ps2, session);
                        ps2.executeUpdate();
                        recordSuccess();
                        return session;
                    }
                }
            });
        } catch (SQLException ex) {
            recordFailure();
            throw new SsoSessionRepositoryException("Failed to persist SSO session", ex);
        }
    }

    private void bindSession(PreparedStatement ps, SsoSession session) throws SQLException {
        ps.setObject(1, session.getId().getValue());
        ps.setString(2, session.getTenant());
        ps.setString(3, session.getHolderHash());
        ps.setObject(4, session.getEstablishedAt().atOffset(ZoneOffset.UTC));
        ps.setObject(5, session.getExpiresAt().atOffset(ZoneOffset.UTC));
        ps.setObject(6, session.getLastUsedAt().atOffset(ZoneOffset.UTC));
        ps.setString(7, session.getState().name());
    }

    @Override
    public Optional<SsoSession> findActiveByTenantAndHolder(String tenant, String holderHash) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = """
        SELECT id, tenant, holder_hash, established_at, expires_at, last_used_at, state
        FROM sso_session
        WHERE tenant = ?
          AND holder_hash = ?
          AND state = 'ACTIVE'
        LIMIT 1
    """;

        try {
            return inTransaction(tenant, c -> {
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setString(1, tenant);
                    ps.setString(2, holderHash);

                    try (ResultSet rs = ps.executeQuery()) {
                        recordSuccess();
                        return rs.next() ? Optional.of(sessionFromResultSet(rs)) : Optional.empty();
                    }
                }
            });
        } catch (SQLException e) {
            log.debug("findActiveByTenantAndHolder error: {}", e.getMessage());
            recordFailure();
            return Optional.empty();
        }
    }

    // =========================================================
    // FIND ACTIVE BY ID
    // =========================================================

    @Override
    public Optional<SsoSession> findActiveById(SsoSessionId sessionId, String tenant) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = """
            SELECT id, tenant, holder_hash, established_at, expires_at, last_used_at, state
            FROM sso_session
            WHERE id = ?
              AND tenant = ?
              AND state = 'ACTIVE'
              AND expires_at > now()
            LIMIT 1
        """;

        try {
            return inTransaction(tenant, c -> {
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setObject(1, sessionId.getValue());
                    ps.setString(2, tenant);

                    try (ResultSet rs = ps.executeQuery()) {
                        recordSuccess();
                        return rs.next() ? Optional.of(sessionFromResultSet(rs)) : Optional.empty();
                    }
                }
            });
        } catch (SQLException e) {
            recordFailure();
            return Optional.empty();
        }
    }

    // =========================================================
    // FIND BY ID (sin filtro tenant — solo para detección cross-tenant AC-04)
    // =========================================================

    @Override
    public Optional<SsoSession> findById(SsoSessionId sessionId) {
        checkCircuit();

        String sql = """
            SELECT id, tenant, holder_hash, established_at, expires_at, last_used_at, state
            FROM sso_session
            WHERE id = ?
            LIMIT 1
        """;

        try {
            return inTransaction(null, c -> {
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setObject(1, sessionId.getValue());

                    try (ResultSet rs = ps.executeQuery()) {
                        recordSuccess();
                        return rs.next() ? Optional.of(sessionFromResultSet(rs)) : Optional.empty();
                    }
                }
            });
        } catch (SQLException e) {
            recordFailure();
            return Optional.empty();
        }
    }

    // =========================================================
    // UPDATE LAST USED AT — touch idle (introducido en US-02/03)
    // NFR-P-549-01 / R-3: llamado de forma no bloqueante desde ReuseSsoSessionWorkflowImpl
    // (CompletableFuture.runAsync) con throttle 1 update/min en el workflow.
    //
    // Índice de soporte verificado: idx_sso_session_tenant_expires (tenant, expires_at)
    // creado en V3__create_sso_session.sql — cubre los scans de expiración por tenant.
    // El UPDATE se resuelve por PK (id) + filtro safety (tenant, state='ACTIVE'):
    // sin índice adicional necesario para esta operación.
    //
    // Diseño de circuit breaker: checkCircuit() se consulta (si el CB está abierto
    // por fallos críticos, no tiene sentido intentar el touch), pero los fallos de
    // esta operación NO abren el CB (no se llama recordFailure()) porque es best-effort:
    // un fallo de touch no debe bloquear save() ni findActiveById().
    // =========================================================

    @Override
    public void updateLastUsedAt(SsoSessionId sessionId, String tenant, Instant lastUsedAt) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = """
            UPDATE sso_session
            SET last_used_at = ?
            WHERE id = ?
              AND tenant = ?
              AND state = 'ACTIVE'
        """;

        try {
            inTransaction(tenant, c -> {
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setObject(1, OffsetDateTime.ofInstant(lastUsedAt, ZoneOffset.UTC));
                    ps.setObject(2, sessionId.getValue());
                    ps.setString(3, tenant);

                    int updated = ps.executeUpdate();
                    if (updated == 0) {
                        log.debug("sso_touch_noop session={}... tenant={} — session GCed or missing",
                                prefix8(sessionId.getValue()), tenant);
                    }

                    recordSuccess();
                    return null;
                }
            });
        } catch (SQLException e) {
            // Best-effort: no registrar como fallo de CB para no afectar operaciones críticas.
            log.warn("sso_touch_db_error session={}... tenant={} error={}",
                    prefix8(sessionId.getValue()), tenant, e.getMessage());
            throw new SsoSessionRepositoryException("Failed update last_used_at", e);
        }
    }

    // =========================================================
    // SUPERSEDE
    // =========================================================

    @Override
    public void supersedeActive(String tenant, String holderHash) {
        ensureTenantSafe(tenant);
        checkCircuit();

        try {
            inTransaction(tenant, c -> {
                supersedeActiveInConnection(c, tenant, holderHash);
                recordSuccess();
                return null;
            });
        } catch (SQLException e) {
            recordFailure();
            throw new SsoSessionRepositoryException("Failed to supersede active SSO sessions", e);
        }
    }

    /** Supersede within an already-open connection/transaction — reused by {@link #save} retry path. */
    private void supersedeActiveInConnection(Connection c, String tenant, String holderHash) throws SQLException {
        String sql = """
            UPDATE sso_session
            SET state = 'SUPERSEDED'
            WHERE tenant = ?
              AND holder_hash = ?
              AND state = 'ACTIVE'
        """;
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, tenant);
            ps.setString(2, holderHash);
            int updated = ps.executeUpdate();
            // B6: NFR-S-547-02 — 8-char prefix of holder hash only
            log.info("Superseded {} rows for tenant={} holderHash={}...", updated, tenant, prefix8(holderHash));
        }
    }

    // =========================================================
    // TERMINATE ACTIVE — US-06 Single Logout (AC-01/AC-02/EC-01)
    // Idempotencia por rows-affected: 0 = ya TERMINATED/ausente (EC-01, no-op de dominio).
    // =========================================================

    @Override
    public int terminateActive(SsoSessionId sessionId, String tenant) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = """
            UPDATE sso_session
            SET state = 'TERMINATED', terminated_at = ?
            WHERE id = ?
              AND tenant = ?
              AND state = 'ACTIVE'
        """;

        try {
            return inTransaction(tenant, c -> {
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setObject(1, OffsetDateTime.ofInstant(Instant.now(clock), ZoneOffset.UTC));
                    ps.setObject(2, sessionId.getValue());
                    ps.setString(3, tenant);

                    int updated = ps.executeUpdate();
                    recordSuccess();
                    return updated;
                }
            });
        } catch (SQLException e) {
            recordFailure();
            throw new SsoSessionRepositoryException("Failed to terminate SSO session", e);
        }
    }

    // =========================================================
    // FIND CLIENTS BY SESSION — US-06 Single Logout (AD-5/ADR-108)
    // Callees a notificar por Back-Channel Logout; clavado por session_id (no por holder_hash).
    // Fail-open en lectura (mismo patrón que findActiveByTenantAndHolder/findActiveById):
    // un fallo de lectura de callees no debe impedir que la sesión ya invalidada complete
    // la redirección al iniciador.
    // =========================================================

    @Override
    public List<String> findClientsBySession(SsoSessionId sessionId, String tenant) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = """
            SELECT DISTINCT client_id
            FROM sso_session_client
            WHERE session_id = ?
              AND tenant = ?
        """;

        try {
            return inTransaction(tenant, c -> {
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setObject(1, sessionId.getValue());
                    ps.setString(2, tenant);

                    try (ResultSet rs = ps.executeQuery()) {
                        List<String> clientIds = new ArrayList<>();
                        while (rs.next()) {
                            clientIds.add(rs.getString("client_id"));
                        }
                        recordSuccess();
                        return List.copyOf(clientIds);
                    }
                }
            });
        } catch (SQLException e) {
            log.warn("findClientsBySession error session={}... tenant={}: {}",
                    prefix8(sessionId.getValue()), tenant, e.getMessage());
            recordFailure();
            return List.of();
        }
    }

    // =========================================================
    // RECORD CLIENT ACTIVITY — US-06 (AD-5/ADR-108)
    // Upsert idempotente poblado por EstablishSsoSessionWorkflow (US-02) y
    // ReuseSsoSessionWorkflowImpl (US-03). Best-effort: nunca lanza — un fallo de tracking
    // no debe bloquear el establecimiento/reutilización de sesión (retrofit aditivo).
    // =========================================================

    @Override
    public void recordClientActivity(SsoSessionId sessionId, String tenant, String clientId) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = """
            INSERT INTO sso_session_client (session_id, tenant, client_id, first_seen_at, last_used_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (session_id, client_id)
            DO UPDATE SET last_used_at = EXCLUDED.last_used_at
        """;

        try {
            inTransaction(tenant, c -> {
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    OffsetDateTime now = OffsetDateTime.ofInstant(Instant.now(clock), ZoneOffset.UTC);
                    ps.setObject(1, sessionId.getValue());
                    ps.setString(2, tenant);
                    ps.setString(3, clientId);
                    ps.setObject(4, now);
                    ps.setObject(5, now);

                    ps.executeUpdate();
                    recordSuccess();
                    return null;
                }
            });
        } catch (SQLException e) {
            // Best-effort (ADR-108): no propagar — no debe romper establish/reuse.
            log.warn("sso_session_client_record_failed session={}... tenant={} error={}",
                    prefix8(sessionId.getValue()), tenant, e.getMessage());
        }
    }

    // =========================================================
    // REVOKE ALL BY TENANT
    // =========================================================

    @Override
    public int revokeAllByTenant(String tenant) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = """
            DELETE FROM sso_session
            WHERE tenant = ?
        """;

        try {
            return inTransaction(tenant, c -> {
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setString(1, tenant);
                    int deleted = ps.executeUpdate();
                    recordSuccess();
                    log.info("Emergency revoke tenant={} count_revoked={}", tenant, deleted);
                    return deleted;
                }
            });
        } catch (SQLException e) {
            recordFailure();
            throw new SsoSessionRepositoryException(
                    "Failed to revoke all SSO sessions for tenant " + tenant, e);
        }
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private boolean isUniqueViolation(SQLException e) {
        // PostgreSQL unique_violation SQL state = 23505
        String sqlState = e.getSQLState();
        return sqlState != null && sqlState.equals("23505");
    }

    private SsoSession sessionFromResultSet(ResultSet rs) throws SQLException {
        String id = rs.getString("id");
        String tenant = rs.getString("tenant");
        String holderHash = rs.getString("holder_hash");

        Instant established = rs.getObject("established_at", OffsetDateTime.class).toInstant();
        Instant expires = rs.getObject("expires_at", OffsetDateTime.class).toInstant();
        String state = rs.getString("state");
        OffsetDateTime lastUsedAtDb = rs.getObject("last_used_at", OffsetDateTime.class);
        Instant lastUsedAt = (lastUsedAtDb != null) ? lastUsedAtDb.toInstant() : established;

        return SsoSession.reconstitute(
                SsoSessionId.of(id),
                tenant,
                holderHash,
                established,
                expires,
                lastUsedAt,
                SsoSessionState.valueOf(state)
        );
    }
}
