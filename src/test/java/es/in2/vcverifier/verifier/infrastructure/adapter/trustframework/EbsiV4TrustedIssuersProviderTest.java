package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EbsiV4TrustedIssuersProviderTest {

    @Mock private BackendConfig backendConfig;
    @Mock private HttpClient httpClient;
    @Mock private HttpResponse<String> httpResponse;
    @Mock private SafeUrlValidator safeUrlValidator;

    private EbsiV4TrustedIssuersProvider provider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        provider = new EbsiV4TrustedIssuersProvider(backendConfig, objectMapper, httpClient, safeUrlValidator);
    }

    @Test
    @SuppressWarnings("unchecked")
    void getIssuerCapabilities_success() throws Exception {
        String capabilitiesJson = "{\"credentialsType\":\"LEARCredentialEmployee\",\"validFor\":{\"from\":\"2024-01-01\",\"to\":\"2025-01-01\"},\"claims\":null}";
        String encodedBody = Base64.getEncoder().encodeToString(capabilitiesJson.getBytes(StandardCharsets.UTF_8));
        String responseBody = "{\"did\":\"did:elsi:VATES-FOO\",\"attributes\":[{\"hash\":\"abc\",\"body\":\"" + encodedBody + "\",\"issuerType\":\"TI\"}]}";

        when(backendConfig.getTrustedIssuerListUri()).thenReturn("https://trusted-issuers.example.com/issuers/");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(responseBody);

        List<IssuerCredentialsCapabilities> result = provider.getIssuerCapabilities("did:elsi:VATES-FOO");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).credentialsType()).isEqualTo("LEARCredentialEmployee");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getIssuerCapabilities_404_throwsIssuerNotAuthorizedException() throws Exception {
        when(backendConfig.getTrustedIssuerListUri()).thenReturn("https://trusted-issuers.example.com/issuers/");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(404);

        assertThatThrownBy(() -> provider.getIssuerCapabilities("did:elsi:UNKNOWN"))
                .isInstanceOf(IssuerNotAuthorizedException.class)
                .hasMessageContaining("UNKNOWN");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getIssuerCapabilities_500_throwsFailedCommunicationException() throws Exception {
        when(backendConfig.getTrustedIssuerListUri()).thenReturn("https://trusted-issuers.example.com/issuers/");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(500);

        assertThatThrownBy(() -> provider.getIssuerCapabilities("did:elsi:VATES-FOO"))
                .isInstanceOf(FailedCommunicationException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void getIssuerCapabilities_ioException_throwsFailedCommunicationException() throws Exception {
        when(backendConfig.getTrustedIssuerListUri()).thenReturn("https://trusted-issuers.example.com/issuers/");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("Connection refused"));

        assertThatThrownBy(() -> provider.getIssuerCapabilities("did:elsi:VATES-FOO"))
                .isInstanceOf(FailedCommunicationException.class);
    }
}
