package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.AccessTokenBuilder;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenGenerationWorkflowTest {

    @Mock private JWTService jwtService;
    @Mock private BackendConfig backendConfig;
    @Mock private ClaimsExtractor claimsExtractor;
    @Mock private AccessTokenBuilder accessTokenBuilder;
    @Mock private SsoSessionRepositoryPort ssoSessionRepositoryPort;
    @Mock private TenantSsoConfigPort tenantSsoConfigPort;
    @Mock private HashingService hashingService;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private TokenGenerationWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new TokenGenerationWorkflow(
                jwtService,
                backendConfig,
                objectMapper,
                List.of(claimsExtractor),
                accessTokenBuilder,
                ssoSessionRepositoryPort,
                tenantSsoConfigPort,
                hashingService);
    }

    private ObjectNode buildW3cCredential(String credentialType) {
        ObjectNode credential = objectMapper.createObjectNode();
        ArrayNode typeArray = credential.putArray("type");
        typeArray.add("VerifiableCredential");
        typeArray.add(credentialType);
        ObjectNode credentialSubject = credential.putObject("credentialSubject");
        credentialSubject.put("id", "did:key:z6MkSubject");
        return credential;
    }

    private ObjectNode buildSdJwtCredential(String vct) {
        ObjectNode credential = objectMapper.createObjectNode();
        credential.put("vct", vct);
        ObjectNode credentialSubject = credential.putObject("credentialSubject");
        credentialSubject.put("id", "did:key:z6MkSubject");
        return credential;
    }

    @Nested
    @DisplayName("extractCredentialType()")
    class ExtractCredentialTypeTests {
        @Test
        @DisplayName("extracts type from W3C type array")
        void extractsFromW3cTypeArray() {
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.4");
            assertThat(workflow.extractCredentialType(credential)).isEqualTo("learcredential.employee.w3c.4");
        }

        @Test
        @DisplayName("extracts type from SD-JWT vct field")
        void extractsFromSdJwtVct() {
            ObjectNode credential = buildSdJwtCredential("learcredential.employee.sd.1");
            assertThat(workflow.extractCredentialType(credential)).isEqualTo("learcredential.employee.sd.1");
        }

        @Test
        @DisplayName("throws when neither type nor vct is present")
        void throwsWhenNoTypeOrVct() {
            ObjectNode credential = objectMapper.createObjectNode();
            assertThatThrownBy(() -> workflow.extractCredentialType(credential))
                    .isInstanceOf(OAuth2AuthenticationException.class);
        }
    }

    @Nested
    @DisplayName("issueAccessToken()")
    class IssueAccessTokenTests {
        @Test
        @DisplayName("delegates access token construction and still builds the ID token")
        void generatesAccessAndIdToken() {
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.4");
            ExtractedClaims claims = ExtractedClaims.builder()
                    .subject("did:key:z6MkSubject")
                    .scope("openid learcredential")
                    .idTokenClaims(Map.of("name", "Test User"))
                    .accessTokenClaims(Map.of("tenant", "VATES-B12345678"))
                    .build();

            when(claimsExtractor.supports("learcredential.employee.w3c.4")).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(accessTokenBuilder.build(any(BuildContext.class))).thenReturn("access-jwt");
            when(jwtService.issueJWT(anyString())).thenReturn("id-jwt");

            Map<String, Object> additionalParams = Map.of(OAuth2ParameterNames.SCOPE, "openid learcredential");
            TokenGenerationWorkflow.Result result = workflow.issueAccessToken(
                    credential,
                    "did:key:client",
                    additionalParams,
                    true,
                    "altia");

            assertThat(result.accessTokenJwt()).isEqualTo("access-jwt");
            assertThat(result.idTokenJwt()).isEqualTo("id-jwt");
            assertThat(result.idTokenClaims()).containsEntry("name", "Test User");
            assertThat(result.scope()).isEqualTo("openid learcredential");
            assertThat(result.subject()).isEqualTo("did:key:z6MkSubject");
            assertThat(result.issueTime()).isNotNull();
            assertThat(result.expirationTime()).isAfterOrEqualTo(result.issueTime());

            ArgumentCaptor<BuildContext> captor = ArgumentCaptor.forClass(BuildContext.class);
            verify(accessTokenBuilder).build(captor.capture());
            BuildContext buildContext = captor.getValue();
            assertThat(buildContext.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
            assertThat(buildContext.tenant()).isEqualTo("altia");
            assertThat(buildContext.audience()).isEqualTo("did:key:client");
            assertThat(buildContext.generateIdToken()).isTrue();
            verify(jwtService, times(1)).issueJWT(anyString());
        }

        @Test
        @DisplayName("generates only access token for client_credentials grant")
        void generatesOnlyAccessToken() {
            ObjectNode credential = buildW3cCredential("learcredential.machine.w3c.3");
            ExtractedClaims claims = ExtractedClaims.builder()
                    .subject("did:key:z6MkMachine")
                    .scope("machine")
                    .idTokenClaims(Map.of())
                    .accessTokenClaims(Map.of("tenant", "VATES-B12345678"))
                    .build();

            when(claimsExtractor.supports("learcredential.machine.w3c.3")).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(accessTokenBuilder.build(any(BuildContext.class))).thenReturn("access-jwt-only");

            TokenGenerationWorkflow.Result result = workflow.issueAccessToken(
                    credential,
                    "https://verifier.example.com",
                    Map.of(),
                    false,
                    "dome");

            assertThat(result.accessTokenJwt()).isEqualTo("access-jwt-only");
            assertThat(result.idTokenJwt()).isNull();
            assertThat(result.idTokenClaims()).isNull();
            verify(accessTokenBuilder).build(any(BuildContext.class));
            verify(jwtService, never()).issueJWT(anyString());
        }

        @Test
        @DisplayName("propagates tenant and additional params into the BuildContext")
        void propagatesBuildContext() {
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.4");
            ExtractedClaims claims = ExtractedClaims.builder()
                    .subject("did:key:z6MkSubject")
                    .scope("openid learcredential")
                    .idTokenClaims(Map.of())
                    .accessTokenClaims(Map.of())
                    .build();

            when(claimsExtractor.supports("learcredential.employee.w3c.4")).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(accessTokenBuilder.build(any(BuildContext.class))).thenReturn("jwt");

            workflow.issueAccessToken(credential, "did:key:client", Map.of("custom", "value"), false, null);

            ArgumentCaptor<BuildContext> captor = ArgumentCaptor.forClass(BuildContext.class);
            verify(accessTokenBuilder).build(captor.capture());
            BuildContext buildContext = captor.getValue();
            assertThat(buildContext.tenant()).isNull();
            assertThat(buildContext.additionalParameters()).containsEntry("custom", "value");
            assertThat(buildContext.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
        }

        @Test
        @DisplayName("throws when no ClaimsExtractor supports the credential type")
        void throwsWhenNoExtractorFound() {
            ObjectNode credential = buildW3cCredential("UnknownCredential");
            when(claimsExtractor.supports("UnknownCredential")).thenReturn(false);

            assertThatThrownBy(() -> workflow.issueAccessToken(credential, "aud", Map.of(), false, "altia"))
                    .isInstanceOf(OAuth2AuthenticationException.class);
            verifyNoInteractions(accessTokenBuilder);
        }
    }

    @Nested
    @DisplayName("buildIdToken() — sid claim stamping (US-06 AD-6 / ADR-109)")
    class SidStampingTests {

        private static final String TENANT = "altia";
        private static final String SUBJECT = "did:key:z6MkSubject";
        private static final String HOLDER_HASH = "hash-of-subject";

        private ExtractedClaims baseClaims() {
            return ExtractedClaims.builder()
                    .subject(SUBJECT)
                    .scope("openid learcredential")
                    .idTokenClaims(Map.of())
                    .accessTokenClaims(Map.of())
                    .build();
        }

        private void stubHappyPathUpTo(ObjectNode credential, ExtractedClaims claims, String credentialType) {
            when(claimsExtractor.supports(credentialType)).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(accessTokenBuilder.build(any(BuildContext.class))).thenReturn("access-jwt");
        }

        /** Captura el payload JSON (sin firmar) pasado a jwtService.issueJWT(...) y lo parsea. */
        private com.fasterxml.jackson.databind.JsonNode capturedIdTokenPayload() {
            ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
            verify(jwtService).issueJWT(payloadCaptor.capture());
            try {
                return objectMapper.readTree(payloadCaptor.getValue());
            } catch (Exception e) {
                throw new AssertionError("id_token payload no es JSON válido", e);
            }
        }

        @Test
        @DisplayName("stamps sid when tenant SSO enabled and session active")
        void buildIdToken_stampsSidWhenTenantSsoEnabledAndSessionActive() {
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.4");
            stubHappyPathUpTo(credential, baseClaims(), "learcredential.employee.w3c.4");
            when(jwtService.issueJWT(anyString())).thenReturn("id-jwt");

            TenantSsoConfig config = mock(TenantSsoConfig.class);
            when(config.ssoEnabled()).thenReturn(true);
            when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config));
            when(hashingService.sha256(SUBJECT)).thenReturn(HOLDER_HASH);

            SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));
            when(ssoSessionRepositoryPort.findActiveByTenantAndHolder(TENANT, HOLDER_HASH))
                    .thenReturn(Optional.of(session));

            workflow.issueAccessToken(credential, "did:key:client", Map.of(), true, TENANT);

            assertThat(capturedIdTokenPayload().get("sid").asText())
                    .isEqualTo(session.getId().getValue());
        }

        @Test
        @DisplayName("omits sid when no active SSO session exists")
        void buildIdToken_omitsSidWhenNoActiveSession() {
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.4");
            stubHappyPathUpTo(credential, baseClaims(), "learcredential.employee.w3c.4");
            when(jwtService.issueJWT(anyString())).thenReturn("id-jwt");

            TenantSsoConfig config = mock(TenantSsoConfig.class);
            when(config.ssoEnabled()).thenReturn(true);
            when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config));
            when(hashingService.sha256(SUBJECT)).thenReturn(HOLDER_HASH);
            when(ssoSessionRepositoryPort.findActiveByTenantAndHolder(TENANT, HOLDER_HASH))
                    .thenReturn(Optional.empty());

            workflow.issueAccessToken(credential, "did:key:client", Map.of(), true, TENANT);

            assertThat(capturedIdTokenPayload().has("sid")).isFalse();
        }

        @Test
        @DisplayName("omits sid when SSO is disabled for the tenant")
        void buildIdToken_omitsSidWhenSsoDisabledForTenant() {
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.4");
            stubHappyPathUpTo(credential, baseClaims(), "learcredential.employee.w3c.4");
            when(jwtService.issueJWT(anyString())).thenReturn("id-jwt");

            TenantSsoConfig config = mock(TenantSsoConfig.class);
            when(config.ssoEnabled()).thenReturn(false);
            when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config));

            workflow.issueAccessToken(credential, "did:key:client", Map.of(), true, TENANT);

            assertThat(capturedIdTokenPayload().has("sid")).isFalse();
            verifyNoInteractions(ssoSessionRepositoryPort, hashingService);
        }
    }
}