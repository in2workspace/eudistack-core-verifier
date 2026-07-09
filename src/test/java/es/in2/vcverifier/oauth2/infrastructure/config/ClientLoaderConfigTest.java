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

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_LOGIN_PAGE_URI;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_TENANT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientLoaderConfigTest {

    @Test
    void retrieveClients_withTenant_storesTenantInClientSettings() {
        // Arrange
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
                "dome", null,
                null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act
        RegisteredClientRepository repo = config.getRegisteredClientRepository();
        RegisteredClient registered = repo.findByClientId("vc-auth-client-dome");

        // Assert
        assertThat(registered).isNotNull();
        assertThat((String) registered.getClientSettings().getSetting(CLIENT_SETTING_TENANT)).isEqualTo("dome");
    }

    @Test
    void retrieveClients_withNullTenant_doesNotSetTenantSetting() {
        // Arrange
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
                null, null, null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act
        RegisteredClientRepository repo = config.getRegisteredClientRepository();
        RegisteredClient registered = repo.findByClientId("vc-auth-client-no-tenant");

        // Assert
        assertThat(registered).isNotNull();
        assertThat(registered.getClientSettings().getSettings()).doesNotContainKey(CLIENT_SETTING_TENANT);
    }

    @Test
    void retrieveClients_withInvalidTenant_throwsException() {
        // Arrange
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
                "INVALID TENANT WITH SPACES!", null, null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act & Assert
        assertThatThrownBy(config::getRegisteredClientRepository)
                .isInstanceOf(ClientLoadingException.class);
    }

    @Test
    void retrieveClients_withValidTenantFormats_succeeds() {
        // Arrange
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
                "my-tenant-123", null, null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act
        RegisteredClientRepository repo = config.getRegisteredClientRepository();
        RegisteredClient registered = repo.findByClientId("vc-auth-client-hyphen");

        // Assert
        assertThat(registered).isNotNull();
        assertThat((String) registered.getClientSettings().getSetting(CLIENT_SETTING_TENANT)).isEqualTo("my-tenant-123");
    }

    @Test
    void retrieveClients_withLoginPageUri_storesLoginPageUriInClientSettings() {
        // Arrange
        String loginPageUri = "https://custom-login.example.com/auth";
        ClientData clientData = new ClientData(
                null, "https://app.example.com",
                "vc-auth-client-login", null,
                List.of("https://app.example.com/callback"),
                List.of("openid", "learcredential"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://app.example.com"),
                true, null, null,
                null, loginPageUri, null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act
        RegisteredClientRepository repo = config.getRegisteredClientRepository();
        RegisteredClient registered = repo.findByClientId("vc-auth-client-login");

        // Assert
        assertThat(registered).isNotNull();
        assertThat((String) registered.getClientSettings().getSetting(CLIENT_SETTING_LOGIN_PAGE_URI)).isEqualTo(loginPageUri);
        assertThat(allowedOrigins)
                .as("loginPageUri origin should be added to allowedClientsOrigins")
                .contains("https://custom-login.example.com");
    }

    @Test
    void retrieveClients_withMultipleRedirectUris_addsAllHttpOriginsToAllowedOrigins() {
        // Arrange
        ClientData clientData = new ClientData(
                null, "https://main-app.example.com",
                "vc-auth-client-multi", null,
                List.of(
                        "https://main-app.example.com/callback",
                        "https://admin.example.com/callback",
                        "myapp://oauth/callback"  // custom scheme — must be skipped
                ),
                List.of("openid"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://main-app.example.com"),
                true, null, null,
                null, null, null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act
        config.getRegisteredClientRepository();

        // Assert
        assertThat(allowedOrigins)
                .as("url origin must be present")
                .contains("https://main-app.example.com");
        assertThat(allowedOrigins)
                .as("secondary redirect URI origin must be present")
                .contains("https://admin.example.com");
        assertThat(allowedOrigins)
                .as("custom-scheme redirect URI must not be added")
                .noneMatch(o -> o.startsWith("myapp"));
    }

    @Test
    void retrieveClients_withRedirectUriSameOriginAsUrl_doesNotDuplicate() {
        // Arrange
        ClientData clientData = new ClientData(
                null, "https://app.example.com",
                "vc-auth-client-same-origin", null,
                List.of("https://app.example.com/callback"),
                List.of("openid"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://app.example.com"),
                true, null, null,
                null, null, null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act
        config.getRegisteredClientRepository();

        // Assert
        assertThat(allowedOrigins)
                .as("same origin must not be duplicated")
                .hasSize(1)
                .contains("https://app.example.com");
    }

    @Test
    void retrieveClients_withNonHttpsLoginPageUri_throwsException() {
        // Arrange
        ClientData clientData = new ClientData(
                null, "https://app.example.com",
                "vc-auth-client-bad-login", null,
                List.of("https://app.example.com/callback"),
                List.of("openid"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://app.example.com"),
                true, null, null,
                null, "http://insecure.example.com/login", null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act & Assert
        assertThatThrownBy(config::getRegisteredClientRepository)
                .isInstanceOf(ClientLoadingException.class);
    }

    @Test
    void retrieveClients_withMixedCaseAndDefaultPortUrl_normalizesAndDoesNotDuplicate() {
        // Arrange
        ClientData clientData = new ClientData(
                null, "https://App.Example.com:443",
                "vc-auth-client-mixed-case", null,
                List.of("https://app.example.com/callback"),
                List.of("openid"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://app.example.com"),
                true, null, null,
                null, null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act
        config.getRegisteredClientRepository();

        // Assert
        assertThat(allowedOrigins)
                .as("mixed-case/default-port origin must normalize to the same entry")
                .hasSize(1)
                .contains("https://app.example.com");
    }

    @Test
    void retrieveClients_withUppercaseSchemeRedirectUri_stillAddsOrigin() {
        // Arrange
        ClientData clientData = new ClientData(
                null, "https://main-app.example.com",
                "vc-auth-client-uppercase-scheme", null,
                List.of("HTTPS://app.example.com/callback"),
                List.of("openid"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://main-app.example.com"),
                true, null, null,
                null, null, null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act
        config.getRegisteredClientRepository();

        // Assert
        assertThat(allowedOrigins)
                .as("redirect URI scheme comparison must be case-insensitive (RFC 3986 3.1)")
                .contains("https://app.example.com");
    }

    @Test
    void retrieveClients_withUppercaseSchemeLoginPageUri_doesNotThrowAndAddsOrigin() {
        // Arrange
        ClientData clientData = new ClientData(
                null, "https://app.example.com",
                "vc-auth-client-uppercase-login", null,
                List.of("https://app.example.com/callback"),
                List.of("openid"),
                List.of("none"),
                List.of("authorization_code"),
                false,
                List.of("https://app.example.com"),
                true, null, null,
                null, "HTTPS://custom-login.example.com/auth", null
        );

        ClientRegistryProvider provider = mock(ClientRegistryProvider.class);
        when(provider.retrieveClients()).thenReturn(
                ExternalTrustedListYamlData.builder().clients(List.of(clientData)).build());

        Set<String> allowedOrigins = new HashSet<>();
        ClientLoaderConfig config = new ClientLoaderConfig(provider, allowedOrigins);

        // Act
        config.getRegisteredClientRepository();

        // Assert
        assertThat(allowedOrigins)
                .as("loginPageUri scheme comparison must be case-insensitive (RFC 3986 3.1)")
                .contains("https://custom-login.example.com");
    }
}
