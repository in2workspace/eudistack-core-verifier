package es.in2.vcverifier.verifier.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.model.dcql.CredentialQuery;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.domain.service.DcqlProfileResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationRequestBuildWorkflowTest {

    @Mock private JWTService jwtService;
    @Mock private CryptoComponent cryptoComponent;
    @Mock private BackendConfig backendConfig;
    @Mock private CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    @Mock private DcqlProfileResolver dcqlProfileResolver;

    private AuthorizationRequestBuildWorkflow workflow;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        workflow = new AuthorizationRequestBuildWorkflow(
                jwtService, cryptoComponent, backendConfig,
                cacheStoreForAuthorizationRequestJWT,
                dcqlProfileResolver, objectMapper
        );
    }

    private RegisteredClient createDummyClient(String clientName) {
        return RegisteredClient.withId("1234")
                .clientId("did:key:test")
                .clientName(clientName)
                .authorizationGrantType(new AuthorizationGrantType("authorization_code"))
                .redirectUri("https://verifier.example.com/callback")
                .build();
    }

    @Test
    @DisplayName("execute() builds JWT, generates openid4vp URL, and caches the result")
    void execute_buildsJwtAndGeneratesUrl() {
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery("lear_employee_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("eu.europa.ec.eudi.lce.1"), null), null)
        ));
        when(dcqlProfileResolver.resolve("openid learcredential")).thenReturn(dcqlQuery);
        when(cryptoComponent.getClientId()).thenReturn("did:key:z6Mk...");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.issueJWTwithOI4VPType(anyString())).thenReturn("signed-jwt-content");

        RegisteredClient client = createDummyClient("My Client");
        AuthorizationRequestBuildWorkflow.Result result = workflow.buildAuthorizationRequest(client, "openid learcredential", "state-123", null);

        assertThat(result.signedAuthRequestJwt()).isEqualTo("signed-jwt-content");
        assertThat(result.openid4vpUrl()).startsWith("openid4vp://");
        assertThat(result.openid4vpUrl()).contains("client_id=");
        assertThat(result.openid4vpUrl()).contains("request_uri=");
        assertThat(result.nonce()).isNotBlank();

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).issueJWTwithOI4VPType(payloadCaptor.capture());
        String payload = payloadCaptor.getValue();
        assertThat(payload).contains("client_metadata");

        // Verify JWT was cached
        verify(cacheStoreForAuthorizationRequestJWT).add(eq(result.nonce()), any(AuthorizationRequestJWT.class));
        // EUD-252 (F1): the OID4VP nonce is returned (the caller caches it atomically with the
        // authorization request), and it is the one embedded in the signed request object
        assertThat(result.vpNonce()).isNotBlank();
        assertThat(payload).contains("\"nonce\":\"" + result.vpNonce() + "\"");
    }

    @Test
    @DisplayName("buildAuthorizationRequest() delegates scope resolution to DcqlProfileResolver")
    void buildAuthorizationRequest_delegatesScopeResolution() {
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery("lear_employee_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("eu.europa.ec.eudi.lce.1"), null), null)
        ));
        when(dcqlProfileResolver.resolve("openid learcredential.employee")).thenReturn(dcqlQuery);
        when(cryptoComponent.getClientId()).thenReturn("did:key:testkey");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.issueJWTwithOI4VPType(anyString())).thenReturn("signed");

        RegisteredClient client = createDummyClient("Client");
        workflow.buildAuthorizationRequest(client, "openid learcredential.employee", "my-state", null);

        verify(dcqlProfileResolver).resolve("openid learcredential.employee");
    }

    @Test
    @DisplayName("buildAuthorizationRequest() restricts the DCQL query when access_profile is issuer_access")
    void buildAuthorizationRequest_issuerAccessProfile_restrictsDcqlQuery() throws Exception {
        // Arrange
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery("lear_employee_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("learcredential.employee.sd.1"), null), null),
                new CredentialQuery("lear_machine_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("learcredential.machine.sd.1"), null), null)
        ));
        when(dcqlProfileResolver.resolve("openid learcredential")).thenReturn(dcqlQuery);
        when(cryptoComponent.getClientId()).thenReturn("did:key:testkey");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.issueJWTwithOI4VPType(anyString())).thenReturn("signed");

        // Act
        workflow.buildAuthorizationRequest(createDummyClient("Client"), "openid learcredential", "state-ia", "issuer_access");

        // Assert
        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).issueJWTwithOI4VPType(payloadCaptor.capture());
        JsonNode credentials = objectMapper.readTree(payloadCaptor.getValue()).get("dcql_query").get("credentials");
        assertThat(credentials).hasSize(2);
        assertThat(credentials.get(0).get("id").asText()).isEqualTo("lear_employee_sd_jwt_onboarding_execute");
        assertThat(credentials.get(0).get("claims")).isNotNull();
        assertThat(credentials.get(1).get("id").asText()).isEqualTo("lear_employee_sd_jwt_sysadmin");
    }

    @Test
    @DisplayName("buildAuthorizationRequest() leaves the DCQL query untouched when access_profile is unknown")
    void buildAuthorizationRequest_unknownAccessProfile_leavesDcqlQueryUntouched() throws Exception {
        // Arrange
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery("lear_employee_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("learcredential.employee.sd.1"), null), null)
        ));
        when(dcqlProfileResolver.resolve("openid learcredential")).thenReturn(dcqlQuery);
        when(cryptoComponent.getClientId()).thenReturn("did:key:testkey");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.issueJWTwithOI4VPType(anyString())).thenReturn("signed");

        // Act
        workflow.buildAuthorizationRequest(createDummyClient("Client"), "openid learcredential", "state-unk", "something_else");

        // Assert
        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).issueJWTwithOI4VPType(payloadCaptor.capture());
        JsonNode credentials = objectMapper.readTree(payloadCaptor.getValue()).get("dcql_query").get("credentials");
        assertThat(credentials).hasSize(1);
        assertThat(credentials.get(0).get("id").asText()).isEqualTo("lear_employee_sd_jwt");
        assertThat(credentials.get(0).has("claims")).isFalse();
    }

    @Test
    @DisplayName("buildAuthorizationRequest() leaves the DCQL query untouched when access_profile is blank")
    void buildAuthorizationRequest_blankAccessProfile_leavesDcqlQueryUntouched() throws Exception {
        // Arrange
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery("lear_employee_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("learcredential.employee.sd.1"), null), null)
        ));
        when(dcqlProfileResolver.resolve("openid learcredential")).thenReturn(dcqlQuery);
        when(cryptoComponent.getClientId()).thenReturn("did:key:testkey");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.issueJWTwithOI4VPType(anyString())).thenReturn("signed");

        // Act
        workflow.buildAuthorizationRequest(createDummyClient("Client"), "openid learcredential", "state-blank", "  ");

        // Assert
        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).issueJWTwithOI4VPType(payloadCaptor.capture());
        JsonNode credentials = objectMapper.readTree(payloadCaptor.getValue()).get("dcql_query").get("credentials");
        assertThat(credentials).hasSize(1);
        assertThat(credentials.get(0).has("claims")).isFalse();
    }

    @Test
    @DisplayName("execute() passes the correct payload structure to JWTService")
    void execute_passesCorrectPayload() {
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery("lear_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("eu.europa.ec.eudi.lce.1"), null), null)
        ));
        when(dcqlProfileResolver.resolve(anyString())).thenReturn(dcqlQuery);
        when(cryptoComponent.getClientId()).thenReturn("did:key:testkey");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.issueJWTwithOI4VPType(anyString())).thenReturn("signed");

        RegisteredClient client = createDummyClient("Client");
        workflow.buildAuthorizationRequest(client, "openid learcredential", "my-state", null);

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).issueJWTwithOI4VPType(payloadCaptor.capture());

        String payload = payloadCaptor.getValue();
        assertThat(payload).contains("did:key:testkey");
        assertThat(payload).contains("response_uri");
        assertThat(payload).contains("dcql_query");
        assertThat(payload).contains("vp_token");
        assertThat(payload).contains("my-state");
        // OID4VP §5.8: aud MUST be "https://self-issued.me/v2"
        assertThat(payload).contains("https://self-issued.me/v2");
        // OID4VP §5.9: client_id_scheme removed (prefix embedded in client_id)
        assertThat(payload).doesNotContain("client_id_scheme");
    }

    @Test
    @DisplayName("buildJwtPayload includes client_metadata for did: prefix client_id")
    void execute_includesClientMetadataForDidPrefix() throws Exception {
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery("lear_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("eu.europa.ec.eudi.lce.1"), null), null)
        ));
        when(dcqlProfileResolver.resolve(anyString())).thenReturn(dcqlQuery);
        when(cryptoComponent.getClientId()).thenReturn("did:key:z6Mk...");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.issueJWTwithOI4VPType(anyString())).thenReturn("signed");

        RegisteredClient client = createDummyClient("Client");
        workflow.buildAuthorizationRequest(client, "openid learcredential", "state-1", null);

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).issueJWTwithOI4VPType(payloadCaptor.capture());

        String payload = payloadCaptor.getValue();
        assertThat(payload).contains("client_metadata");
        assertThat(payload).contains("vp_formats_supported");
    }

    @Test
    @DisplayName("buildJwtPayload includes client_metadata for x509_hash: prefix client_id")
    void execute_includesClientMetadataForX509HashPrefix() throws Exception {
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery("lear_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("eu.europa.ec.eudi.lce.1"), null), null)
        ));
        when(dcqlProfileResolver.resolve(anyString())).thenReturn(dcqlQuery);
        when(cryptoComponent.getClientId()).thenReturn("x509_hash:abc123def456");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.issueJWTwithOI4VPType(anyString())).thenReturn("signed");

        RegisteredClient client = createDummyClient("Client");
        workflow.buildAuthorizationRequest(client, "openid learcredential", "state-2", null);

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).issueJWTwithOI4VPType(payloadCaptor.capture());

        String payload = payloadCaptor.getValue();
        assertThat(payload).contains("client_metadata");
        assertThat(payload).contains("vp_formats_supported");
    }

    @Test
    @DisplayName("client_metadata contains correct vp_formats_supported structure with ES256")
    void execute_clientMetadataHasCorrectStructure() throws Exception {
        DcqlQuery dcqlQuery = new DcqlQuery(List.of(
                new CredentialQuery("lear_sd_jwt", "dc+sd-jwt",
                        new CredentialQuery.CredentialMeta(List.of("eu.europa.ec.eudi.lce.1"), null), null)
        ));
        when(dcqlProfileResolver.resolve(anyString())).thenReturn(dcqlQuery);
        when(cryptoComponent.getClientId()).thenReturn("did:key:z6MkTest");
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
        when(jwtService.issueJWTwithOI4VPType(anyString())).thenReturn("signed");

        RegisteredClient client = createDummyClient("Client");
        workflow.buildAuthorizationRequest(client, "openid learcredential", "state-3", null);

        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService).issueJWTwithOI4VPType(payloadCaptor.capture());

        // Parse the JWT claims JSON to inspect client_metadata structure
        JsonNode claims = objectMapper.readTree(payloadCaptor.getValue());
        JsonNode clientMetadata = claims.get("client_metadata");
        assertThat(clientMetadata).isNotNull();

        JsonNode formats = clientMetadata.get("vp_formats_supported");
        assertThat(formats).isNotNull();

        // dc+sd-jwt format
        JsonNode sdJwt = formats.get("dc+sd-jwt");
        assertThat(sdJwt).isNotNull();
        assertThat(sdJwt.get("sd-jwt_alg_values").get(0).asText()).isEqualTo("ES256");
        assertThat(sdJwt.get("kb-jwt_alg_values").get(0).asText()).isEqualTo("ES256");
        assertThat(sdJwt.has("alg_values_supported")).isFalse();

        // jwt_vc_json format
        JsonNode jwtVc = formats.get("jwt_vc_json");
        assertThat(jwtVc).isNotNull();
        assertThat(jwtVc.get("alg_values_supported").get(0).asText()).isEqualTo("ES256");
        assertThat(jwtVc.has("sd-jwt_alg_values")).isFalse();
        assertThat(jwtVc.has("kb-jwt_alg_values")).isFalse();
    }
}
