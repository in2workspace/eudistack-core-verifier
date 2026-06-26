package es.in2.vcverifier.sso.infrastructure.persistence;

import es.in2.vcverifier.sso.domain.exception.SsoSessionRepositoryException;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionState;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import javax.sql.DataSource;
import java.lang.reflect.Constructor;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * JDBC implementation of {@link SsoSessionRepositoryPort}.
 * - Executes queries in tenant schema by setting search_path.
 * - Uses a simple in-memory circuit breaker to fail-closed when DB is unstable.
 * - Handles partial unique constraint on (tenant, holder_hash) WHERE state='ACTIVE'
 *   by attempting supersede on duplicate-key and retrying once (idempotent behavior).
 */
@Repository
@Slf4j
public class SsoSessionJdbcRepository implements SsoSessionRepositoryPort {

    private static final String TENANT_PATTERN = "^[a-z0-9-]{1,64}$";

    private final DataSource dataSource;

    // Statement timeout in milliseconds
    private final int statementTimeoutMs = 5_000;

    // Simple circuit breaker
    private final int failureThreshold = 5;
    private final long openMillis = 60_000;
    private final AtomicInteger failureCounter = new AtomicInteger(0);
    private volatile long openUntil = 0L;

    public SsoSessionJdbcRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

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
    private static String prefix8(String s) {
        if (s == null) return "null";
        return s.length() <= 8 ? s : s.substring(0, 8);
    }

    /**
     * Sets search_path to the quoted tenant schema + public.
     * Fail-closed: if this fails, we must NOT continue with unqualified SQL
     * as queries could hit the wrong schema (cross-tenant data leak risk).
     */
    private void setTenantSearchPath(Connection c, String tenant) throws SQLException {
        // Tenant identifier is quoted to support hyphens (e.g. "my-tenant")
        // which are valid per TENANT_PATTERN but require quoting in PostgreSQL.
        String sql = "SET LOCAL search_path = \"" + tenant + "\", public";
        try (PreparedStatement s = c.prepareStatement(sql)) {
            s.execute();
        }
    }

    private void setStatementTimeout(Connection c) throws SQLException {
        try (PreparedStatement s = c.prepareStatement("SET LOCAL statement_timeout = " + statementTimeoutMs)) {
            s.execute();
        }
    }

    @Override
    public SsoSession save(SsoSession session) {

        ensureTenantSafe(session.getTenant());
        checkCircuit();

        String insertSql = "INSERT INTO sso_session (id, tenant, holder_hash, established_at, expires_at, state) VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection c = dataSource.getConnection()) {
            // Fail-closed: if search_path cannot be set, abort to avoid cross-tenant writes.
            setTenantSearchPath(c, session.getTenant());
            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(insertSql)) {
                ps.setString(1, session.getId().getValue());
                ps.setString(2, session.getTenant());
                ps.setString(3, session.getHolderHash());
                ps.setObject(4, session.getEstablishedAt().atOffset(ZoneOffset.UTC));
                ps.setObject(5, session.getExpiresAt().atOffset(ZoneOffset.UTC));
                ps.setString(6, session.getState().name());
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
                        ps2.setString(1, session.getId().getValue());
                        ps2.setString(2, session.getTenant());
                        ps2.setString(3, session.getHolderHash());
                        ps2.setObject(4, session.getEstablishedAt().atOffset(ZoneOffset.UTC));
                        ps2.setObject(5, session.getExpiresAt().atOffset(ZoneOffset.UTC));
                        ps2.setString(6, session.getState().name());
                        ps2.executeUpdate();
                        recordSuccess();
                        return session;
                    } catch (SQLException e2) {
                        log.error("Retry insert failed: {}", e2.getMessage());
                        recordFailure();
                        throw new SsoSessionRepositoryException("Failed to persist SSO session after retry", e2);
                    }
                }

                throw new SsoSessionRepositoryException("Failed to persist SSO session", e);
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

        String sql = "SELECT id, tenant, holder_hash, established_at, expires_at, state FROM sso_session WHERE tenant = ? AND holder_hash = ? AND state = 'ACTIVE' LIMIT 1";

        try (Connection c = dataSource.getConnection()) {
            // Fail-closed: if search_path cannot be set, abort to avoid reading from the wrong schema.
            setTenantSearchPath(c, tenant);
            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, tenant);
                ps.setString(2, holderHash);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        SsoSession session = sessionFromResultSet(rs);
                        recordSuccess();
                        return Optional.of(session);
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

    @Override
    public void supersedeActive(String tenant, String holderHash) {
        ensureTenantSafe(tenant);
        checkCircuit();

        String sql = "UPDATE sso_session SET state = 'SUPERSEDED' WHERE tenant = ? AND holder_hash = ? AND state = 'ACTIVE'";

        try (Connection c = dataSource.getConnection()) {
            // Fail-closed: if search_path cannot be set, abort to avoid updating the wrong schema.
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

        try {
            Constructor<SsoSession> ctor = SsoSession.class.getDeclaredConstructor(
                    SsoSessionId.class, String.class, String.class, Instant.class, Instant.class, SsoSessionState.class);
            ctor.setAccessible(true);
            return ctor.newInstance(SsoSessionId.of(id), tenant, holderHash, established, expires, SsoSessionState.valueOf(state));
        } catch (ReflectiveOperationException ex) {
            throw new SsoSessionRepositoryException("Failed to reconstruct SsoSession from DB", ex);
        }
    }
}
