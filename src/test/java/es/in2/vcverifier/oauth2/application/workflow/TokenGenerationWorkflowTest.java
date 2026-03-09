package es.in2.vcverifier.oauth2.application.workflow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import es.in2.vcverifier.shared.crypto.JWTService;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenGenerationWorkflowTest {

    @Mock private JWTService jwtService;
    @Mock private BackendConfig backendConfig;
    @Mock private ClaimsExtractor claimsExtractor;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private TokenGenerationWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new TokenGenerationWorkflow(jwtService, backendConfig, objectMapper, List.of(claimsExtractor));
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
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.1");
            assertThat(workflow.extractCredentialType(credential)).isEqualTo("learcredential.employee.w3c.1");
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
        @DisplayName("generates access token and ID token for authorization_code grant")
        void generatesAccessAndIdToken() {
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.1");
            ExtractedClaims claims = ExtractedClaims.builder()
                    .subject("did:key:z6MkSubject")
                    .scope("openid learcredential")
                    .idTokenClaims(Map.of("name", "Test User"))
                    .accessTokenClaims(Map.of("tenant", "VATES-B12345678"))
                    .build();

            when(claimsExtractor.supports("learcredential.employee.w3c.1")).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(jwtService.issueJWT(anyString())).thenReturn("access-jwt", "id-jwt");

            Map<String, Object> additionalParams = Map.of(
                    OAuth2ParameterNames.SCOPE, "openid learcredential"
            );
            TokenGenerationWorkflow.Result result = workflow.issueAccessToken(credential, "did:key:client", additionalParams, true);

            assertThat(result.accessTokenJwt()).isEqualTo("access-jwt");
            assertThat(result.idTokenJwt()).isEqualTo("id-jwt");
            assertThat(result.scope()).isEqualTo("openid learcredential");
            assertThat(result.subject()).isEqualTo("did:key:z6MkSubject");
            assertThat(result.issueTime()).isNotNull();
            assertThat(result.expirationTime()).isAfterOrEqualTo(result.issueTime());

            verify(jwtService, times(2)).issueJWT(anyString());
        }

        @Test
        @DisplayName("generates only access token for client_credentials grant")
        void generatesOnlyAccessToken() {
            ObjectNode credential = buildW3cCredential("learcredential.machine.w3c.1");
            ExtractedClaims claims = ExtractedClaims.builder()
                    .subject("did:key:z6MkMachine")
                    .scope("machine")
                    .idTokenClaims(Map.of())
                    .accessTokenClaims(Map.of("tenant", "VATES-B12345678"))
                    .build();

            when(claimsExtractor.supports("learcredential.machine.w3c.1")).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(jwtService.issueJWT(anyString())).thenReturn("access-jwt-only");

            TokenGenerationWorkflow.Result result = workflow.issueAccessToken(credential, "https://verifier.example.com", Map.of(), false);

            assertThat(result.accessTokenJwt()).isEqualTo("access-jwt-only");
            assertThat(result.idTokenJwt()).isNull();

            verify(jwtService, times(1)).issueJWT(anyString());
        }

        @Test
        @DisplayName("includes credential_type, tenant and embeds in the JWT payload")
        void includesCredentialTypeAndEmbedsInAccessToken() {
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.1");
            ExtractedClaims claims = ExtractedClaims.builder()
                    .subject("did:key:z6MkSubject")
                    .scope("openid learcredential")
                    .idTokenClaims(Map.of())
                    .accessTokenClaims(Map.of("tenant", "VATES-B12345678"))
                    .accessTokenEmbeds(Map.of("mandatee", Map.of("firstName", "John")))
                    .build();

            when(claimsExtractor.supports("learcredential.employee.w3c.1")).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(jwtService.issueJWT(anyString())).thenReturn("jwt");

            workflow.issueAccessToken(credential, "did:key:client", Map.of(), false);

            ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
            verify(jwtService).issueJWT(captor.capture());
            String payload = captor.getValue();
            assertThat(payload).contains("\"credential_type\":\"learcredential.employee.w3c.1\"");
            assertThat(payload).contains("\"tenant\":\"VATES-B12345678\"");
            assertThat(payload).contains("\"mandatee\":");
            assertThat(payload).doesNotContain("\"vc\":");
        }

        @Test
        @DisplayName("includes credential_type and embeds in the ID token payload")
        void includesCredentialTypeAndEmbedsInIdToken() {
            ObjectNode credential = buildW3cCredential("learcredential.employee.w3c.1");
            ExtractedClaims claims = ExtractedClaims.builder()
                    .subject("did:key:z6MkSubject")
                    .scope("openid learcredential")
                    .idTokenClaims(Map.of("name", "John Doe"))
                    .idTokenEmbeds(Map.of(
                            "mandatee", Map.of("firstName", "John", "lastName", "Doe"),
                            "mandator", Map.of("organizationIdentifier", "VATES-B12345678"),
                            "power", List.of(Map.of("function", "Onboarding", "action", "Execute"))
                    ))
                    .accessTokenClaims(Map.of("tenant", "VATES-B12345678"))
                    .accessTokenEmbeds(Map.of("mandatee", Map.of("firstName", "John")))
                    .build();

            when(claimsExtractor.supports("learcredential.employee.w3c.1")).thenReturn(true);
            when(claimsExtractor.extract(credential)).thenReturn(claims);
            when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");
            when(jwtService.issueJWT(anyString())).thenReturn("access-jwt", "id-jwt");

            Map<String, Object> additionalParams = Map.of(
                    OAuth2ParameterNames.SCOPE, "openid learcredential"
            );
            workflow.issueAccessToken(credential, "did:key:client", additionalParams, true);

            ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
            verify(jwtService, times(2)).issueJWT(captor.capture());
            // Second call is the ID token
            String idTokenPayload = captor.getAllValues().get(1);
            assertThat(idTokenPayload).contains("\"credential_type\":\"learcredential.employee.w3c.1\"");
            assertThat(idTokenPayload).contains("\"mandatee\":");
            assertThat(idTokenPayload).contains("\"mandator\":");
            assertThat(idTokenPayload).contains("\"power\":");
            assertThat(idTokenPayload).contains("\"name\":\"John Doe\"");
        }

        @Test
        @DisplayName("throws when no ClaimsExtractor supports the credential type")
        void throwsWhenNoExtractorFound() {
            ObjectNode credential = buildW3cCredential("UnknownCredential");
            when(claimsExtractor.supports("UnknownCredential")).thenReturn(false);

            assertThatThrownBy(() -> workflow.issueAccessToken(credential, "aud", Map.of(), false))
                    .isInstanceOf(OAuth2AuthenticationException.class);
        }
    }
}
