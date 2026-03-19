package es.in2.vcverifier.oauth2.infrastructure.config;

import es.in2.vcverifier.verifier.domain.model.ClientData;
import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import es.in2.vcverifier.oauth2.domain.exception.ClientLoadingException;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_TENANT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClientLoaderConfigTest {

    @Test
    void retrieveClients_withTenant_storesTenantInClientSettings() {
        ClientData clientData = new ClientData(
                null, "https://app.dome.example.com",
                "vc-auth-client-dome", null,
                List.of("https://app.dome.example.com/callback"),
                List.of("openid", "learcredential"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://app.dome.example.com"),
                true, null, null,
                "dome"
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        RegisteredClientRepository repo = config.getRegisteredClientRepository();
        RegisteredClient registered = repo.findByClientId("vc-auth-client-dome");

        assertNotNull(registered);
        assertEquals("dome", registered.getClientSettings().getSetting(CLIENT_SETTING_TENANT));
    }

    @Test
    void retrieveClients_withNullTenant_doesNotSetTenantSetting() {
        ClientData clientData = new ClientData(
                null, "https://app.example.com",
                "vc-auth-client-no-tenant", null,
                List.of("https://app.example.com/callback"),
                List.of("openid"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://app.example.com"),
                true, null, null,
                null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        RegisteredClientRepository repo = config.getRegisteredClientRepository();
        RegisteredClient registered = repo.findByClientId("vc-auth-client-no-tenant");

        assertNotNull(registered);
        assertFalse(registered.getClientSettings().getSettings().containsKey(CLIENT_SETTING_TENANT));
    }

    @Test
    void retrieveClients_withInvalidTenant_throwsException() {
        ClientData clientData = new ClientData(
                null, "https://app.example.com",
                "vc-auth-client-bad", null,
                List.of("https://app.example.com/callback"),
                List.of("openid"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://app.example.com"),
                true, null, null,
                "INVALID TENANT WITH SPACES!"
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        assertThrows(ClientLoadingException.class, config::getRegisteredClientRepository);
    }

    @Test
    void retrieveClients_withValidTenantFormats_succeeds() {
        ClientData clientData = new ClientData(
                null, "https://app.example.com",
                "vc-auth-client-hyphen", null,
                List.of("https://app.example.com/callback"),
                List.of("openid"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://app.example.com"),
                true, null, null,
                "my-tenant-123"
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        RegisteredClientRepository repo = config.getRegisteredClientRepository();
        RegisteredClient registered = repo.findByClientId("vc-auth-client-hyphen");

        assertNotNull(registered);
        assertEquals("my-tenant-123", registered.getClientSettings().getSetting(CLIENT_SETTING_TENANT));
    }
}
