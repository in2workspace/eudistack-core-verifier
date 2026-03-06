package es.in2.vcverifier.verifier.infrastructure.adapter.clientregistry;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.verifier.domain.exception.RemoteFileFetchException;
import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RemoteClientRegistryProviderTest {

    @Mock private BackendConfig backendConfig;
    @Mock private HttpClient httpClient;
    @Mock private HttpResponse<String> httpResponse;

    private RemoteClientRegistryProvider provider;

    @BeforeEach
    void setUp() {
        provider = new RemoteClientRegistryProvider(backendConfig, httpClient);
    }

    @Test
    @SuppressWarnings("unchecked")
    void loadClients_success() throws Exception {
        String yamlBody = """
                clients:
                  - clientId: "test-client"
                    url: "http://test.example.com"
                    clientAuthenticationMethods: ["none"]
                    authorizationGrantTypes: ["authorization_code"]
                    redirectUris: ["http://test.example.com/callback"]
                    scopes: ["openid"]
                    requireAuthorizationConsent: false
                    requireProofKey: true
                """;

        when(backendConfig.getClientsRepositoryUri()).thenReturn("https://remote.example.com/clients.yaml");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(yamlBody);

        ExternalTrustedListYamlData result = provider.loadClients();

        assertThat(result).isNotNull();
        assertThat(result.clients()).hasSize(1);
        assertThat(result.clients().get(0).clientId()).isEqualTo("test-client");
    }

    @Test
    @SuppressWarnings("unchecked")
    void loadClients_non200_throwsRemoteFileFetchException() throws Exception {
        when(backendConfig.getClientsRepositoryUri()).thenReturn("https://remote.example.com/clients.yaml");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(500);

        assertThatThrownBy(() -> provider.loadClients())
                .isInstanceOf(RemoteFileFetchException.class)
                .hasMessageContaining("500");
    }

    @Test
    @SuppressWarnings("unchecked")
    void loadClients_ioException_throwsRemoteFileFetchException() throws Exception {
        when(backendConfig.getClientsRepositoryUri()).thenReturn("https://remote.example.com/clients.yaml");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("Connection timeout"));

        assertThatThrownBy(() -> provider.loadClients())
                .isInstanceOf(RemoteFileFetchException.class)
                .hasMessageContaining("remote");
    }
}
