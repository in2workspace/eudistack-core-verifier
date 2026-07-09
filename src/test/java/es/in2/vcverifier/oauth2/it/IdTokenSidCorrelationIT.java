package es.in2.vcverifier.oauth2.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.oauth2.application.workflow.TokenGenerationWorkflow;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.infrastructure.persistence.SsoSessionJdbcRepository;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.AccessTokenBuilder;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * IT — US-06 Task 33 (DELTA-03/AD-6, ADR-109): confirma que el claim {@code sid} estampado por
 * {@link TokenGenerationWorkflow} en emisión corresponde a la fila real de {@code sso_session}
 * establecida previamente para el mismo {@code (tenant, subject)}.
 * <p>
 * ADR-109 señala como riesgo residual que {@code sha256(subject)} calculado en emisión (US-06)
 * debe mapear al mismo {@code holder_hash} calculado en establecimiento (US-02); este IT lo
 * verifica end-to-end contra Postgres real (Testcontainers) usando la {@link HashingService} real
 * en ambos lados, sin mockearla — si dejara de coincidir, corresponde escalar spec-delta y
 * conmutar a la Opción B del ADR.
 * <p>
 * No usa {@code @SpringBootTest}: instancia {@link TokenGenerationWorkflow} directamente (mismo
 * patrón ligero que {@code SsoSessionClientTrackingIT}, Task 30), con {@link SsoSessionJdbcRepository}
 * y {@link HashingService} reales contra el contenedor, y el resto de colaboradores (no relevantes
 * para esta correlación) mockeados — evita el arranque completo del contexto Spring.
 */
@Testcontainers
class IdTokenSidCorrelationIT {

    private static final String TENANT = "tenant-a";
    private static final String SUBJECT = "did:key:z6MkSubject";
    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.4";

    @Container
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("vcverifier")
                    .withUsername("test")
                    .withPassword("test");

    private static DataSource dataSource;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeAll
    static void startContainerAndCreateSchema() throws SQLException {
        dataSource = new DriverManagerDataSource(
                postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());

        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            // Mirrors V3__create_sso_session.sql + V5__add_last_used_at_sso_session.sql
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
        }
    }

    @AfterAll
    static void stopContainer() {
        postgres.stop();
    }

    @BeforeEach
    void cleanTable() throws SQLException {
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE TABLE sso_session");
        }
    }

    @Test
    void issueAccessToken_stampsSidMatchingRealSsoSessionRow() {
        HashingService hashingService = new HashingService();
        SsoSessionJdbcRepository sessionRepository = new SsoSessionJdbcRepository(dataSource, Clock.systemUTC());

        String holderHash = hashingService.sha256(SUBJECT);
        SsoSession establishedSession = SsoSession.establish(TENANT, holderHash, Duration.ofHours(1));
        sessionRepository.save(establishedSession);

        JWTService jwtService = mock(JWTService.class);
        when(jwtService.issueJWT(anyString())).thenAnswer(invocation -> invocation.getArgument(0));

        BackendConfig backendConfig = mock(BackendConfig.class);
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(backendConfig.getAccessTokenExpirationSeconds()).thenReturn(300L);
        when(backendConfig.getIdTokenExpirationSeconds()).thenReturn(300L);

        ClaimsExtractor claimsExtractor = mock(ClaimsExtractor.class);
        when(claimsExtractor.supports(CREDENTIAL_TYPE)).thenReturn(true);
        when(claimsExtractor.extract(any(JsonNode.class))).thenReturn(ExtractedClaims.builder()
                .subject(SUBJECT)
                .scope("openid learcredential")
                .idTokenClaims(Map.of())
                .accessTokenClaims(Map.of())
                .build());

        AccessTokenBuilder accessTokenBuilder = mock(AccessTokenBuilder.class);
        when(accessTokenBuilder.build(any())).thenReturn("access-jwt");

        SchemaProfileRegistry schemaProfileRegistry = mock(SchemaProfileRegistry.class);
        when(schemaProfileRegistry.findByConfigId(CREDENTIAL_TYPE)).thenReturn(Optional.of(new SchemaProfile(
                CREDENTIAL_TYPE, null, null, null,
                Set.of("authorization_code"), false, null, null, true)));

        TenantSsoConfigPort tenantSsoConfigPort = mock(TenantSsoConfigPort.class);
        TenantSsoConfig config = new TenantSsoConfig(
                TENANT, "", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)),
                List.of());
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config));

        TokenGenerationWorkflow workflow = new TokenGenerationWorkflow(
                jwtService,
                backendConfig,
                objectMapper,
                List.of(claimsExtractor),
                accessTokenBuilder,
                schemaProfileRegistry,
                sessionRepository,
                tenantSsoConfigPort,
                hashingService);

        ObjectNode credential = objectMapper.createObjectNode();
        ArrayNode typeArray = credential.putArray("type");
        typeArray.add("VerifiableCredential");
        typeArray.add(CREDENTIAL_TYPE);

        TokenGenerationWorkflow.Result result = workflow.issueAccessToken(
                credential, "did:key:client", Map.of(), true, TENANT);

        JsonNode idTokenPayload = readPayload(result.idTokenJwt());
        assertThat(idTokenPayload.has("sid")).isTrue();
        String sidFromToken = idTokenPayload.get("sid").asText();

        // AC-01/AC-04: el sid emitido debe corresponder a la fila real persistida en establecimiento,
        // no a un valor derivado en memoria — se re-consulta contra la BD real.
        SsoSession persistedSession = sessionRepository.findActiveByTenantAndHolder(TENANT, holderHash)
                .orElseThrow(() -> new AssertionError("expected an ACTIVE session persisted in Postgres"));

        assertThat(sidFromToken).isEqualTo(persistedSession.getId().getValue());
        assertThat(sidFromToken).isEqualTo(establishedSession.getId().getValue());
    }

    private JsonNode readPayload(String rawJson) {
        try {
            return objectMapper.readTree(rawJson);
        } catch (Exception e) {
            throw new AssertionError("id_token payload no es JSON válido", e);
        }
    }

    /**
     * {@link DataSource} mínimo sin pool de conexiones — mismo patrón que
     * {@code SsoSessionClientTrackingIT} (Task 30): suficiente porque este IT no ejercita
     * concurrencia real de conexiones.
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
