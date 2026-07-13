package es.in2.vcverifier.sso.infrastructure.persistence;

import es.in2.vcverifier.sso.domain.exception.SsoSessionRepositoryException;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionState;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.*;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

@Repository
@Slf4j
public class SsoSessionJdbcRepository implements SsoSessionRepositoryPort {

    private static final String TENANT_PATTERN = "^[a-z0-9-]{1,64}$";

    private final DataSource dataSource;

    private final int statementTimeoutMs = 5_000;

    private final int failureThreshold = 5;
    private final long openMillis = 60_000;
    private final AtomicInteger failureCounter = new AtomicInteger(0);
    private volatile long openUntil = 0L;

    public SsoSessionJdbcRepository(DataSource dataSource) {
        this.dataSource = dataSource;
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
        String sql = "SET LOCAL search_path = \"" + tenant + "\", public";
        try (PreparedStatement s = c.prepareStatement(sql)) {
            s.execute();
        }
    }

    private void setStatementTimeout(Connection c) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(
                "SET LOCAL statement_timeout = " + statementTimeoutMs)) {
            s.execute();
        }
    }

    // =========================================================
    // SAVE (UNCHANGED)
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

        try (Connection c = dataSource.getConnection()) {

            setTenantSearchPath(c, session.getTenant());
            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(insertSql)) {
                ps.setObject(1, session.getId().getValue());
                ps.setString(2, session.getTenant());
                ps.setString(3, session.getHolderHash());
                ps.setObject(4, session.getEstablishedAt().atOffset(ZoneOffset.UTC));
                ps.setObject(5, session.getExpiresAt().atOffset(ZoneOffset.UTC));
                ps.setObject(6, session.getLastUsedAt().atOffset(ZoneOffset.UTC));
                ps.setString(7, session.getState().name());

                ps.executeUpdate();
                recordSuccess();
                return session;

            } catch (SQLException e) {
                // B6: NFR-S-547-02 — log only 8-char prefix of session id and holder hash
                log.warn("Insert failed for session {}...: {}", prefix8(session.getId().getValue()), e.getMessage());
                recordFailure();

                if (isUniqueViolation(e)) {
                    log.info("Unique active session exists for tenant={} holderHash={}... - attempting supersede and retry",
                            session.getTenant(), prefix8(session.getHolderHash()));
                    try {
                    supersedeActive(session.getTenant(), session.getHolderHash());
                    } catch (Exception supEx) {
                        log.warn("Supersede attempt failed: {}", supEx.getMessage());
                    }

                    // retry insert once
                    try (PreparedStatement ps2 = c.prepareStatement(insertSql)) {
                        ps2.setObject(1, session.getId().getValue());
                        ps2.setString(2, session.getTenant());
                        ps2.setString(3, session.getHolderHash());
                        ps2.setObject(4, session.getEstablishedAt().atOffset(ZoneOffset.UTC));
                        ps2.setObject(5, session.getExpiresAt().atOffset(ZoneOffset.UTC));
                        ps2.setObject(6, session.getLastUsedAt().atOffset(ZoneOffset.UTC));
                        ps2.setString(7, session.getState().name());

                        ps2.executeUpdate();
                        recordSuccess();
                        return session;

                    } catch (SQLException e2) {
                        log.error("Retry insert failed: {}", e2.getMessage());
                        recordFailure();
                        throw new SsoSessionRepositoryException("Failed to persist SSO session after retry", e2);
                    }
                }

                throw new SsoSessionRepositoryException("Failed to persist session", e);
            }

        } catch (SQLException ex) {
            recordFailure();
            throw new SsoSessionRepositoryException("Failed to persist SSO session (connection error)", ex);
        }
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

        try (Connection c = dataSource.getConnection()) {

            setTenantSearchPath(c, tenant);
            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, tenant);
                ps.setString(2, holderHash);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        recordSuccess();
                        return Optional.of(sessionFromResultSet(rs));
                    } else {
                    recordSuccess();
                    return Optional.empty();
                    }
                }
            }

        } catch (SQLException e) {
            log.debug("findActiveByTenantAndHolder error: {}", e.getMessage());
            recordFailure();
            return Optional.empty();
        }
    }

    // =========================================================
    // NEW: FIND ACTIVE BY ID
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

        try (Connection c = dataSource.getConnection()) {

            setTenantSearchPath(c, tenant);
            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setObject(1, sessionId.getValue());
                ps.setString(2, tenant);

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        recordSuccess();
                        return Optional.of(sessionFromResultSet(rs));
                    }
                    recordSuccess();
                    return Optional.empty();
                }
            }

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

        try (Connection c = dataSource.getConnection()) {

            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setObject(1, sessionId.getValue());

                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        recordSuccess();
                        return Optional.of(sessionFromResultSet(rs));
                    }
                    recordSuccess();
                    return Optional.empty();
                }
            }

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

        try (Connection c = dataSource.getConnection()) {

            setTenantSearchPath(c, tenant);
            setStatementTimeout(c);

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
            }

        } catch (SQLException e) {
            // Best-effort: no registrar como fallo de CB para no afectar operaciones críticas.
            log.warn("sso_touch_db_error session={}... tenant={} error={}",
                    prefix8(sessionId.getValue()), tenant, e.getMessage());
            throw new SsoSessionRepositoryException("Failed update last_used_at", e);
        }
    }

    // =========================================================
    // SUPSERSEDE (UNCHANGED)
    // =========================================================

    @Override
    public void supersedeActive(String tenant, String holderHash) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = """
            UPDATE sso_session
            SET state = 'SUPERSEDED'
            WHERE tenant = ?
              AND holder_hash = ?
              AND state = 'ACTIVE'
        """;

        try (Connection c = dataSource.getConnection()) {

            setTenantSearchPath(c, tenant);
            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, tenant);
                ps.setString(2, holderHash);

                int updated = ps.executeUpdate();
                // B6: NFR-S-547-02 — 8-char prefix of holder hash only
                log.info("Superseded {} rows for tenant={} holderHash={}...", updated, tenant, prefix8(holderHash));
                recordSuccess();
            }

        } catch (SQLException e) {
            recordFailure();
            throw new SsoSessionRepositoryException("Failed to supersede active SSO sessions", e);
        }
    }

    // =========================================================
    // REVOKE ALL BY TENANT — corte de emergencia (EUDISTACK-554 / US-09)
    // =========================================================

    @Override
    public int revokeAllByTenant(String tenant) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = """
            DELETE FROM sso_session
            WHERE tenant = ?
        """;

        try (Connection c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            setTenantSearchPath(c, tenant);
            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, tenant);
                int deleted = ps.executeUpdate();
                c.commit();
                recordSuccess();
                log.info("Emergency revoke tenant={} count_revoked={}", tenant, deleted);
                return deleted;
            } catch (SQLException ex) {
                c.rollback();
                recordFailure();
                throw new SsoSessionRepositoryException(
                        "Failed to revoke all SSO sessions for tenant " + tenant, ex);
            } finally {
                c.setAutoCommit(true);
            }
        } catch (SQLException ex) {
            recordFailure();
            throw new SsoSessionRepositoryException(
                    "Failed to revoke SSO sessions (connection error) for tenant " + tenant, ex);
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
