package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.application.workflow.ReuseSsoSessionWorkflowImpl;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import es.in2.vcverifier.sso.infrastructure.persistence.SsoSessionJdbcRepository;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * IT — ADR-108/DELTA-02 (US-06 Task 30): round-trip de {@code recordClientActivity} +
 * {@code findClientsBySession} a nivel de repositorio con Postgres real (Testcontainers),
 * y verificación de que los retrofits aditivos de {@code EstablishSsoSessionWorkflow} (Task 28,
 * US-02) y {@code ReuseSsoSessionWorkflowImpl} (Task 29, US-03) pueblan {@code sso_session_client}.
 *
 * No usa {@code @SpringBootTest}: instancia los workflows directamente con un {@link DataSource}
 * real apuntando al contenedor, mismo patrón ligero que {@code SsoDomainTests} pero con BD real
 * en vez de mocks del {@link DataSource}, evitando el arranque completo del contexto Spring
 * (innecesario para esta verificación de persistencia).
 */
@Testcontainers
class SsoSessionClientTrackingIT {

    @Container
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("vcverifier")
                    .withUsername("test")
                    .withPassword("test");

    private static DataSource dataSource;

    @BeforeAll
    static void startContainerAndCreateSchema() throws SQLException {
        dataSource = new DriverManagerDataSource(
                postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());

        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("""
                CREATE TABLE IF NOT EXISTS sso_session (
                    id             TEXT        PRIMARY KEY,
                    tenant         TEXT        NOT NULL,
                    holder_hash    TEXT        NOT NULL,
                    established_at TIMESTAMPTZ NOT NULL,
                    expires_at     TIMESTAMPTZ NOT NULL,
                    last_used_at   TIMESTAMPTZ NOT NULL,
                    state          VARCHAR(32) NOT NULL
                )
                """);
            // Mirrors V6__create_sso_session_client.sql
            s.execute("""
                CREATE TABLE IF NOT EXISTS sso_session_client (
                    session_id     TEXT NOT NULL REFERENCES sso_session(id) ON DELETE CASCADE,
                    tenant         TEXT NOT NULL,
                    client_id      TEXT NOT NULL,
                    first_seen_at  TIMESTAMPTZ NOT NULL,
                    last_used_at   TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (session_id, client_id)
                )
                """);
        }
    }

    @AfterAll
    static void stopContainer() {
        postgres.stop();
    }

    @BeforeEach
    void cleanTables() throws SQLException {
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE TABLE sso_session_client");
            s.execute("TRUNCATE TABLE sso_session CASCADE");
        }
    }

    private SsoSessionJdbcRepository newRepository() {
        return new SsoSessionJdbcRepository(dataSource, Clock.systemUTC());
    }

    // =========================================================
    // ROUND-TRIP A NIVEL DE REPOSITORIO
    // =========================================================

    @Test
    void recordClientActivity_and_findClientsBySession_roundTrip() {
        SsoSessionJdbcRepository repository = newRepository();
        String tenant = "tenant-a";

        SsoSession session = SsoSession.establish(tenant, "holder-hash-1", Duration.ofHours(1));
        repository.save(session);

        repository.recordClientActivity(session.getId(), tenant, "client-a");
        repository.recordClientActivity(session.getId(), tenant, "client-b");

        List<String> clients = repository.findClientsBySession(session.getId(), tenant);

        assertThat(clients).containsExactlyInAnyOrder("client-a", "client-b");
    }

    @Test
    void recordClientActivity_isIdempotentUpsert_noDuplicateRow() throws SQLException {
        SsoSessionJdbcRepository repository = newRepository();
        String tenant = "tenant-a";

        SsoSession session = SsoSession.establish(tenant, "holder-hash-2", Duration.ofHours(1));
        repository.save(session);

        repository.recordClientActivity(session.getId(), tenant, "client-a");
        repository.recordClientActivity(session.getId(), tenant, "client-a");
        repository.recordClientActivity(session.getId(), tenant, "client-a");

        try (Connection c = dataSource.getConnection();
             Statement s = c.createStatement()) {
            var rs = s.executeQuery(
                    "SELECT COUNT(*) FROM sso_session_client WHERE session_id = '"
                            + session.getId().getValue() + "' AND client_id = 'client-a'");
            rs.next();
            assertThat(rs.getInt(1)).isEqualTo(1);
        }
    }

    @Test
    void findClientsBySession_scopesByTenant_doesNotLeakAcrossTenants() {
        SsoSessionJdbcRepository repository = newRepository();

        SsoSession sessionTenantA = SsoSession.establish("tenant-a", "holder-a", Duration.ofHours(1));
        repository.save(sessionTenantA);
        repository.recordClientActivity(sessionTenantA.getId(), "tenant-a", "client-a");

        // Consultar con un tenant distinto al de la sesión no debe devolver el callee.
        List<String> clientsForWrongTenant =
                repository.findClientsBySession(sessionTenantA.getId(), "tenant-b");

        assertThat(clientsForWrongTenant).isEmpty();
    }

    // =========================================================
    // TASK 28 — EstablishSsoSessionWorkflow registra al iniciador
    // =========================================================

    @Test
    void establishSsoSessionWorkflow_execute_recordsInitiatorClientActivity() {
        SsoSessionJdbcRepository repository = newRepository();
        String tenant = "tenant-a";

        TenantSsoConfigPort tenantSsoConfigPort = mock(TenantSsoConfigPort.class);
        SsoAuditPort auditPort = mock(SsoAuditPort.class);
        SsoMetricsPort metricsPort = mock(SsoMetricsPort.class);
        HashingService hashingService = mock(HashingService.class);

        TenantSsoConfig config = mock(TenantSsoConfig.class);
        when(config.ssoEnabled()).thenReturn(true);
        when(tenantSsoConfigPort.getByTenant(tenant)).thenReturn(java.util.Optional.of(config));
        when(tenantSsoConfigPort.resolveTtl(tenant)).thenReturn(SsoSessionTtl.systemDefault());
        when(hashingService.sha256(anyString())).thenReturn("holder-hash-established");

        EstablishSsoSessionWorkflow workflow = new EstablishSsoSessionWorkflow(
                tenantSsoConfigPort, repository, auditPort, metricsPort, hashingService, Clock.systemUTC());

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor descriptor =
                workflow.execute(new SsoSessionCommand(tenant, "sub-value", "initiator-client", "corr-1"));

        assertThat(descriptor).isNotNull();

        List<String> clients = repository.findClientsBySession(
                SsoSessionId.of(descriptor.value()), tenant);

        assertThat(clients).containsExactly("initiator-client");
    }

    // =========================================================
    // TASK 29 — ReuseSsoSessionWorkflowImpl hace upsert del callee en ALLOWED
    // (piggyback en el bloque async throttled: se espera con Awaitility, ya
    // disponible transitivamente vía spring-boot-starter-test — sin nueva dependencia)
    // =========================================================

    @Test
    void reuseSsoSessionWorkflowImpl_allowedReuse_upsertsCalleeClientActivity() {
        SsoSessionJdbcRepository repository = newRepository();
        String tenant = "tenant-a";
        String calleeClientId = "callee-client";

        // Sesión establecida hace 5 min, último uso hace 2 min: idle-valid (< 30 min default)
        // y por encima del throttle de 1 min → dispara el bloque async con el upsert piggyback.
        Instant now = Instant.now();
        Instant establishedAt = now.minus(Duration.ofMinutes(5));
        Instant lastUsedAt = now.minus(Duration.ofMinutes(2));

        SsoSession session = SsoSession.reconstitute(
                SsoSessionId.generate(), tenant, "holder-hash-reuse",
                establishedAt, now.plus(Duration.ofHours(1)), lastUsedAt,
                es.in2.vcverifier.sso.domain.model.SsoSessionState.ACTIVE);
        repository.save(session);

        TenantSsoConfigPort configPort = mock(TenantSsoConfigPort.class);
        SsoAuditPort auditPort = mock(SsoAuditPort.class);
        SsoMetricsPort metricsPort = mock(SsoMetricsPort.class);
        RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);

        TenantSsoConfig config = mock(TenantSsoConfig.class);
        when(config.ssoEnabled()).thenReturn(true);
        when(configPort.getByTenant(tenant)).thenReturn(java.util.Optional.of(config));
        when(configPort.resolveTtl(tenant)).thenReturn(SsoSessionTtl.systemDefault());
        when(configPort.resolveEligibleClients(tenant))
                .thenReturn(TenantSsoCatalog.of(Set.of(SsoEligibleClient.of(calleeClientId))));
        when(registeredClientRepository.findByClientId(calleeClientId))
                .thenReturn(mock(RegisteredClient.class));

        ReuseSsoSessionWorkflowImpl workflow = new ReuseSsoSessionWorkflowImpl(
                configPort, repository, Clock.systemUTC(), auditPort, metricsPort, registeredClientRepository);

        ReuseSsoSessionWorkflow.Result result = workflow.reuse(
                tenant, session.getId().getValue(), null, calleeClientId);

        assertThat(result.status()).isEqualTo(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);

        // El upsert va piggyback en un CompletableFuture.runAsync sin executor inyectable
        // (retrofit aditivo mínimo, Task 29) — se espera de forma acotada con Awaitility.
        await().atMost(3, TimeUnit.SECONDS).untilAsserted(() ->
                assertThat(repository.findClientsBySession(session.getId(), tenant))
                        .contains(calleeClientId));
    }

    /**
     * {@link DataSource} mínimo sin pool de conexiones: suficiente para este IT, que no
     * ejercita concurrencia real de conexiones (cada método abre/cierra la suya, igual que
     * {@link SsoSessionJdbcRepository}).
     */
    private static final class DriverManagerDataSource implements DataSource {
        private final String url;
        private final String user;
        private final String password;

        private DriverManagerDataSource(String url, String user, String password) {
            this.url = url;
            this.user = user;
            this.password = password;
        }

        @Override
        public Connection getConnection() throws SQLException {
            return DriverManager.getConnection(url, user, password);
        }

        @Override
        public Connection getConnection(String username, String pwd) throws SQLException {
            return DriverManager.getConnection(url, username, pwd);
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
            // not needed for tests
        }

        @Override
        public void setLoginTimeout(int seconds) {
            // not needed for tests
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getLogger(getClass().getName());
        }

        @Override
        public <T> T unwrap(Class<T> iface) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }
}
