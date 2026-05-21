package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.AccessTokenBuilder;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
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

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

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
    @Mock private SchemaProfileRegistry schemaProfileRegistry;

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
                schemaProfileRegistry);
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

    private SchemaProfile schemaProfile(String configId, boolean wrapVcInAccessToken, String... grantEligibility) {
        return new SchemaProfile(
                configId,
                null,
                null,
                null,
                Set.of(grantEligibility),
                false,
                null,
                null,
                wrapVcInAccessToken);
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
            when(schemaProfileRegistry.findByConfigId("learcredential.employee.w3c.4")).thenReturn(Optional.of(
                    schemaProfile("learcredential.employee.w3c.4", true, "authorization_code")));
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
            assertThat(result.scope()).isEqualTo("openid learcredential");
            assertThat(result.subject()).isEqualTo("did:key:z6MkSubject");
            assertThat(result.issueTime()).isNotNull();
            assertThat(result.expirationTime()).isAfterOrEqualTo(result.issueTime());

            ArgumentCaptor<BuildContext> captor = ArgumentCaptor.forClass(BuildContext.class);
            verify(accessTokenBuilder).build(captor.capture());
            BuildContext buildContext = captor.getValue();
            assertThat(buildContext.dispatchDecision()).isEqualTo(
                    DispatchDecision.permitted("learcredential.employee.w3c.4", CredentialFormat.BUMPED_V2_0, DispatchReason.BY_TYPE));
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
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(schemaProfileRegistry.findByConfigId("learcredential.machine.w3c.3")).thenReturn(Optional.of(
                    schemaProfile("learcredential.machine.w3c.3", false, "client_credentials")));
            when(accessTokenBuilder.build(any(BuildContext.class))).thenReturn("access-jwt-only");

            TokenGenerationWorkflow.Result result = workflow.issueAccessToken(
                    credential,
                    "https://verifier.example.com",
                    Map.of(),
                    false,
                    "dome");

            assertThat(result.accessTokenJwt()).isEqualTo("access-jwt-only");
            assertThat(result.idTokenJwt()).isNull();
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
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(schemaProfileRegistry.findByConfigId("learcredential.employee.w3c.4")).thenReturn(Optional.of(
                    schemaProfile("learcredential.employee.w3c.4", true, "authorization_code")));
            when(accessTokenBuilder.build(any(BuildContext.class))).thenReturn("jwt");

            workflow.issueAccessToken(credential, "did:key:client", Map.of("custom", "value"), false, null);

            ArgumentCaptor<BuildContext> captor = ArgumentCaptor.forClass(BuildContext.class);
            verify(accessTokenBuilder).build(captor.capture());
            BuildContext buildContext = captor.getValue();
            assertThat(buildContext.tenant()).isNull();
            assertThat(buildContext.additionalParameters()).containsEntry("custom", "value");
            assertThat(buildContext.dispatchDecision().credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
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
}