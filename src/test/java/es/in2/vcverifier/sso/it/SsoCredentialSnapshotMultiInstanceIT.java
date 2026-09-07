package es.in2.vcverifier.sso.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.application.workflow.ReuseSsoSessionWorkflowImpl;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCredentialCipherPort;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import es.in2.vcverifier.sso.infrastructure.crypto.AesGcmSsoCredentialCipherAdapter;
import es.in2.vcverifier.sso.infrastructure.persistence.SsoSessionJdbcRepository;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
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
import java.util.Base64;
import java.util.Set;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * IT — EUD-149 production-readiness (report §7.2): la reutilización SSO ya no depende de una
 * caché en memoria local a la instancia ({@code CacheStore<JsonNode> ssoSessionCredentialCache}).
 * Ese diseño fallaba en silencio a {@code login_required} en cualquier topología con más de una
 * réplica: una petición de reutilización que aterrizaba en una réplica distinta a la que
 * estableció la sesión encontraba siempre un cache miss, aunque la fila en Postgres siguiera
 * {@code ACTIVE} y válida.
 * <p>
 * Este test simula dos réplicas SIN levantar dos procesos: "instancia A" (establece la sesión) e
 * "instancia B" (la reutiliza) son grafos de objetos Java completamente separados —
 * {@link EstablishSsoSessionWorkflow}, {@link ReuseSsoSessionWorkflowImpl},
 * {@link SsoSessionJdbcRepository} y {@link AesGcmSsoCredentialCipherAdapter} propios cada una,
 * sin ningún bean ni caché compartidos — apuntando al mismo Postgres real (Testcontainers). Lo
 * único que comparten (o no, en el segundo test) es el valor de
 * {@code VERIFIER_SSO_CREDENTIAL_ENCRYPTION_KEY}, exactamente como en un despliegue real con
 * ECS Fargate multi-réplica.
 */
@Testcontainers
class SsoCredentialSnapshotMultiInstanceIT {

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
            // Mirrors V3__create_sso_session.sql + V5 (last_used_at) + V8 (credential_snapshot).
            s.execute("""
                CREATE TABLE IF NOT EXISTS sso_session (
                    id             TEXT        PRIMARY KEY,
                    tenant         TEXT        NOT NULL,
                    holder_hash    TEXT        NOT NULL,
                    established_at TIMESTAMPTZ NOT NULL,
                    expires_at     TIMESTAMPTZ NOT NULL,
                    last_used_at   TIMESTAMPTZ NOT NULL,
                    state          VARCHAR(32) NOT NULL,
                    credential_snapshot BYTEA
                )
                """);
        }
    }

    @BeforeEach
    void cleanTable() throws SQLException {
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE TABLE sso_session");
        }
    }

    private static final String TENANT = "tenant-a";
    private static final String HOLDER_SUB = "holder-sub-value";
    private static final String CLIENT_ID = "callee-client";
    private static final String REDIRECT_URI = "https://callee.example/callback";

    /**
     * Escenario principal: instancia A establece, instancia B (misma clave, ningún objeto
     * compartido) reutiliza. Antes de este fix, esto habría caído siempre a LOGIN_REQUIRED por
     * cache miss aunque la fila estuviera ACTIVE — ahora debe llegar a ALLOWED.
     */
    @Test
    void reuseOnDifferentInstance_withSameSharedKey_succeeds() {
        String sharedKey = randomBase64Key();

        // ── "Instancia A" — establece la sesión ──────────────────────────────
        SsoSessionJdbcRepository repositoryOnA = new SsoSessionJdbcRepository(dataSource, Clock.systemUTC());
        SsoCredentialCipherPort cipherOnA = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(sharedKey));
        EstablishSsoSessionWorkflow establishWorkflow = buildEstablishWorkflow(repositoryOnA, cipherOnA);

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor descriptor = establishWorkflow.execute(
                new SsoSessionCommand(TENANT, HOLDER_SUB, "initiator-client", "corr-1",
                        "{\"sub\":\"" + HOLDER_SUB + "\"}"));

        assertThat(descriptor).isNotNull();

        // ── "Instancia B" — objetos completamente nuevos, misma clave compartida ────────────
        SsoSessionJdbcRepository repositoryOnB = new SsoSessionJdbcRepository(dataSource, Clock.systemUTC());
        SsoCredentialCipherPort cipherOnB = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(sharedKey));
        ReuseSsoSessionWorkflow.Result result = reuseOn(repositoryOnB, cipherOnB, descriptor.value());

        assertThat(result.status()).isEqualTo(ReuseSsoSessionWorkflow.Result.Status.ALLOWED);
        assertThat(result.redirectUrl()).contains("code=");
    }

    /**
     * Control negativo: si la "instancia B" tiene una clave distinta (una réplica mal
     * configurada, o el escenario histórico sin clave compartida en absoluto), la reutilización
     * debe fallar cerrado a LOGIN_REQUIRED — nunca emitir un code con claims que no pudo
     * verificar que fueran las correctas para esa sesión.
     */
    @Test
    void reuseOnDifferentInstance_withDifferentKey_failsClosedToLoginRequired() {
        SsoSessionJdbcRepository repositoryOnA = new SsoSessionJdbcRepository(dataSource, Clock.systemUTC());
        SsoCredentialCipherPort cipherOnA = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomBase64Key()));
        EstablishSsoSessionWorkflow establishWorkflow = buildEstablishWorkflow(repositoryOnA, cipherOnA);

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor descriptor = establishWorkflow.execute(
                new SsoSessionCommand(TENANT, HOLDER_SUB, "initiator-client", "corr-2",
                        "{\"sub\":\"" + HOLDER_SUB + "\"}"));

        assertThat(descriptor).isNotNull();

        SsoSessionJdbcRepository repositoryOnB = new SsoSessionJdbcRepository(dataSource, Clock.systemUTC());
        SsoCredentialCipherPort cipherOnB = new AesGcmSsoCredentialCipherAdapter(backendConfigWithKey(randomBase64Key()));
        ReuseSsoSessionWorkflow.Result result = reuseOn(repositoryOnB, cipherOnB, descriptor.value());

        assertThat(result.status()).isEqualTo(ReuseSsoSessionWorkflow.Result.Status.LOGIN_REQUIRED);
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private EstablishSsoSessionWorkflow buildEstablishWorkflow(
            SsoSessionJdbcRepository repository, SsoCredentialCipherPort cipherPort) {

        TenantSsoConfigPort tenantSsoConfigPort = mock(TenantSsoConfigPort.class);
        HashingService hashingService = mock(HashingService.class);

        TenantSsoConfig config = mock(TenantSsoConfig.class);
        when(config.ssoEnabled()).thenReturn(true);
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(java.util.Optional.of(config));
        when(tenantSsoConfigPort.resolveTtl(TENANT)).thenReturn(SsoSessionTtl.systemDefault());
        when(hashingService.sha256(anyString())).thenReturn(HOLDER_SUB);

        return new EstablishSsoSessionWorkflow(
                tenantSsoConfigPort, repository, mock(SsoAuditPort.class), mock(SsoMetricsPort.class),
                hashingService, Clock.systemUTC(), cipherPort);
    }

    private ReuseSsoSessionWorkflow.Result reuseOn(
            SsoSessionJdbcRepository repository, SsoCredentialCipherPort cipherPort, String sessionId) {

        TenantSsoConfigPort configPort = mock(TenantSsoConfigPort.class);
        RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
        AuthorizationResponseProcessorService authorizationResponseProcessorService =
                mock(AuthorizationResponseProcessorService.class);

        TenantSsoConfig config = mock(TenantSsoConfig.class);
        when(config.ssoEnabled()).thenReturn(true);
        when(configPort.getByTenant(TENANT)).thenReturn(java.util.Optional.of(config));
        when(configPort.resolveTtl(TENANT)).thenReturn(SsoSessionTtl.systemDefault());
        when(configPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(Set.of(SsoEligibleClient.of(CLIENT_ID))));

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClient.getRedirectUris()).thenReturn(Set.of(REDIRECT_URI));
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient);

        when(authorizationResponseProcessorService.issueCodeForReusedSession(
                anyString(), anyString(), any(), anyString(), any(), any(), any(), any()))
                .thenReturn(REDIRECT_URI + "?code=fake-code&state=xyz");

        ReuseSsoSessionWorkflowImpl workflow = new ReuseSsoSessionWorkflowImpl(
                configPort, repository, Clock.systemUTC(), mock(SsoAuditPort.class), mock(SsoMetricsPort.class),
                registeredClientRepository, authorizationResponseProcessorService, cipherPort, new ObjectMapper());

        AuthorizationContext ctx = AuthorizationContext.builder()
                .redirectUri(REDIRECT_URI)
                .scope("openid")
                .state("xyz")
                .build();

        return workflow.reuse(TENANT, sessionId, ctx, CLIENT_ID);
    }

    private static BackendConfig backendConfigWithKey(String base64Key) {
        BackendConfig backendConfig = mock(BackendConfig.class);
        when(backendConfig.getSsoCredentialEncryptionKey()).thenReturn(base64Key);
        return backendConfig;
    }

    private static String randomBase64Key() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    /**
     * {@link DataSource} mínimo sin pool de conexiones — mismo patrón que
     * {@code SsoSessionClientTrackingIT}, suficiente porque cada método abre/cierra su propia
     * conexión igual que {@link SsoSessionJdbcRepository}.
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
