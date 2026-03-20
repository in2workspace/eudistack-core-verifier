package es.in2.vcverifier.verifier.application.workflow;

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
    @Mock private CacheStore<String> cacheForNonceByState;
    @Mock private DcqlProfileResolver dcqlProfileResolver;

    private AuthorizationRequestBuildWorkflow workflow;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        workflow = new AuthorizationRequestBuildWorkflow(
                jwtService, cryptoComponent, backendConfig,
                cacheStoreForAuthorizationRequestJWT, cacheForNonceByState,
                dcqlProfileResolver, objectMapper
        );
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

        AuthorizationRequestBuildWorkflow.Result result = workflow.buildAuthorizationRequest("My Client", "openid learcredential", "state-123");

        assertThat(result.signedAuthRequestJwt()).isEqualTo("signed-jwt-content");
        assertThat(result.openid4vpUrl()).startsWith("openid4vp://");
        assertThat(result.openid4vpUrl()).contains("client_id=");
        assertThat(result.openid4vpUrl()).contains("request_uri=");
        assertThat(result.nonce()).isNotBlank();
        assertThat(result.homeUri()).isEqualTo("My Client");

        // Verify JWT was cached
        verify(cacheStoreForAuthorizationRequestJWT).add(eq(result.nonce()), any(AuthorizationRequestJWT.class));
        // Verify nonce-by-state was cached
        verify(cacheForNonceByState).add(eq("state-123"), anyString());
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

        workflow.buildAuthorizationRequest("Client", "openid learcredential.employee", "my-state");

        verify(dcqlProfileResolver).resolve("openid learcredential.employee");
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

        workflow.buildAuthorizationRequest("Client", "openid learcredential", "my-state");

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
}
