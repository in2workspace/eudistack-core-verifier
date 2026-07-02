package es.in2.vcverifier.sso.infrastructure.persistence;

import es.in2.vcverifier.sso.domain.exception.SsoCatalogRepositoryException;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * Adaptador JDBC para {@link SsoCatalogRepositoryPort}.
 * Persiste el catálogo de clientes SSO elegibles en la tabla {@code sso_eligible_client}
 * (migración V6) siguiendo el mismo patrón de aislamiento multi-tenant que
 * {@link SsoSessionJdbcRepository}:
 * <ul>
 *   <li>{@code search_path} configurado por conexión al schema del tenant.</li>
 *   <li>Columna {@code tenant} presente en la tabla para doble filtro defensivo.</li>
 *   <li>Timeout de sentencia de 5 s para limitar latencia en el camino de escritura.</li>
 * </ul>
 *
 * AC-04 / EC-04: {@code addClient} es idempotente gracias a
 * {@code INSERT ... ON CONFLICT (tenant, client_id) DO NOTHING};
 * devuelve {@code true} solo si el cliente fue efectivamente insertado.
 */
@Repository
@Slf4j
public class SsoCatalogJdbcAdapter implements SsoCatalogRepositoryPort {

    private static final String TENANT_PATTERN   = "^[a-z0-9-]{1,64}$";
    private static final int    STATEMENT_TIMEOUT = 5_000;

    private final DataSource dataSource;

    public SsoCatalogJdbcAdapter(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    // =========================================================
    // PUBLIC API
    // =========================================================

    @Override
    public boolean addClient(String tenant, SsoEligibleClient client) {
        ensureTenantSafe(tenant);

        String sql = """
                INSERT INTO sso_eligible_client (tenant, client_id)
                VALUES (?, ?)
                ON CONFLICT (tenant, client_id) DO NOTHING
                """;

        try (Connection c = dataSource.getConnection()) {
            setTenantSearchPath(c, tenant);
            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, tenant);
                ps.setString(2, client.clientId());
                boolean added = ps.executeUpdate() > 0;
                log.debug("event=sso_catalog_db_add tenant={} clientId={} added={}",
                        tenant, client.clientId(), added);
                return added;
            }

        } catch (SQLException e) {
            log.error("event=sso_catalog_db_add_error tenant={} clientId={} error={}",
                    tenant, client.clientId(), e.getMessage());
            throw new SsoCatalogRepositoryException("Failed to add SSO eligible client", e);
        }
    }

    @Override
    public boolean removeClient(String tenant, SsoEligibleClient client) {
        ensureTenantSafe(tenant);

        String sql = """
                DELETE FROM sso_eligible_client
                WHERE tenant = ?
                  AND client_id = ?
                """;

        try (Connection c = dataSource.getConnection()) {
            setTenantSearchPath(c, tenant);
            setStatementTimeout(c);

            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, tenant);
                ps.setString(2, client.clientId());
                boolean removed = ps.executeUpdate() > 0;
                log.debug("event=sso_catalog_db_remove tenant={} clientId={} removed={}",
                        tenant, client.clientId(), removed);
                return removed;
            }

        } catch (SQLException e) {
            log.error("event=sso_catalog_db_remove_error tenant={} clientId={} error={}",
                    tenant, client.clientId(), e.getMessage());
            throw new SsoCatalogRepositoryException("Failed to remove SSO eligible client", e);
        }
    }

    // =========================================================
    // HELPERS — mismo patrón que SsoSessionJdbcRepository
    // =========================================================

    private void ensureTenantSafe(String tenant) {
        if (tenant == null || !tenant.matches(TENANT_PATTERN)) {
            throw new IllegalArgumentException("Invalid tenant identifier: " + tenant);
        }
    }

    private void setTenantSearchPath(Connection c, String tenant) throws SQLException {
        String sql = "SET LOCAL search_path = \"" + tenant + "\", public";
        try (PreparedStatement s = c.prepareStatement(sql)) {
            s.execute();
        }
    }

    private void setStatementTimeout(Connection c) throws SQLException {
        try (PreparedStatement s = c.prepareStatement(
                "SET LOCAL statement_timeout = " + STATEMENT_TIMEOUT)) {
            s.execute();
        }
    }
}
