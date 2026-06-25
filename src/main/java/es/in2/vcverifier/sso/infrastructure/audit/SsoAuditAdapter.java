package es.in2.vcverifier.sso.infrastructure.audit;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

@Component
@Slf4j
@RequiredArgsConstructor
public class SsoAuditAdapter implements SsoAuditPort {

    private static final String TENANT_PATTERN = "^[a-z0-9-]{1,64}$";
    private static final String INSERT_SQL =
            "INSERT INTO sso_audit_event " +
            "(tenant, event_type, client_id, holder_hash, message, correlation_id, occurred_at, session_id_prefix) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    private final DataSource dataSource;

    @Override
    public void publish(SsoAuditEvent event) {
        // NFR-S-547-02: only log the session id prefix, never the full value
        log.info("SSO_AUDIT eventType={} tenant={} clientId={} outcome={} correlationId={} sessionIdPrefix={}",
                event.getEventType().name(),
                event.getTenant(),
                event.getClientId(),
                event.getOutcome(),
                event.getCorrelationId(),
                event.getSessionIdPrefix());

        String tenant = event.getTenant();
        if (tenant == null || !tenant.matches(TENANT_PATTERN)) {
            log.warn("SSO audit: skipping DB write — invalid tenant '{}'", tenant);
            return;
        }

        try (Connection c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                try (PreparedStatement s = c.prepareStatement(
                        "SET LOCAL search_path = \"" + tenant + "\", public")) {
                    s.execute();
                }
                try (PreparedStatement ps = c.prepareStatement(INSERT_SQL)) {
                    ps.setString(1, tenant);
                    ps.setString(2, event.getEventType().name());
                    ps.setString(3, event.getClientId());
                    ps.setString(4, event.getHolderHash());
                    ps.setString(5, event.getOutcome());
                    ps.setString(6, event.getCorrelationId());
                    ps.setObject(7, event.getOccurredAt()
                            .atOffset(java.time.ZoneOffset.UTC));
                    ps.setString(8, event.getSessionIdPrefix());
                    ps.executeUpdate();
                }
                c.commit();
            } catch (SQLException e) {
                try { c.rollback(); } catch (SQLException rb) {
                    log.debug("Audit rollback failed: {}", rb.getMessage());
                }
                log.warn("SSO audit: DB write failed for tenant={} eventType={}: {}",
                        tenant, event.getEventType().name(), e.getMessage());
            }
        } catch (SQLException ex) {
            log.warn("SSO audit: connection error for tenant={}: {}", tenant, ex.getMessage());
        }
    }
}
