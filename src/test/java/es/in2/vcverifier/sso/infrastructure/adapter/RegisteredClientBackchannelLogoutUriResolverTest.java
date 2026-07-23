package es.in2.vcverifier.sso.infrastructure.adapter;

import es.in2.vcverifier.shared.domain.exception.SsrfProtectionException;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.Optional;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_BACKCHANNEL_LOGOUT_URI;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

/**
 * Unit — US-06 (AD-4/DELTA-01) / [B3] SEC-14: {@code RegisteredClientBackchannelLogoutUriResolver}
 * valida cada URI candidata (primaria vía {@code ClientSettings}, fallback vía el catálogo de
 * elegibles) con {@link SafeUrlValidator} antes de devolverla. Una URI rechazada por SSRF se
 * trata exactamente igual que una ausente (Optional.empty — AC-04, backchannel_skipped): nunca
 * propaga la excepción, para no romper el dispatch de otros callees de la misma sesión.
 */
@ExtendWith(MockitoExtension.class)
class RegisteredClientBackchannelLogoutUriResolverTest {

    private static final String TENANT = "tenant-a";
    private static final String CLIENT_ID = "callee-client";

    @Mock private RegisteredClientRepository registeredClientRepository;
    @Mock private TenantSsoConfigPort tenantSsoConfigPort;
    @Mock private SafeUrlValidator safeUrlValidator;
    @Mock private RegisteredClient registeredClient;

    @Test
    void resolve_withSafeClientSettingsUri_returnsUri() {
        String uri = "https://callee.example.com/backchannel-logout";
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getClientSettings()).thenReturn(
                ClientSettings.builder().setting(CLIENT_SETTING_BACKCHANNEL_LOGOUT_URI, uri).build());

        var resolver = new RegisteredClientBackchannelLogoutUriResolver(
                registeredClientRepository, tenantSsoConfigPort, safeUrlValidator);

        Optional<String> result = resolver.resolve(TENANT, CLIENT_ID);

        assertThat(result).contains(uri);
    }

    @Test
    void resolve_withSsrfRejectedClientSettingsUri_fallsBackToCatalogLikeAnAbsentPrimaryUri() {
        String unsafeUri = "http://169.254.169.254/backchannel-logout";
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getClientSettings()).thenReturn(
                ClientSettings.builder().setting(CLIENT_SETTING_BACKCHANNEL_LOGOUT_URI, unsafeUri).build());
        doThrow(new SsrfProtectionException("Cloud metadata addresses are not allowed"))
                .when(safeUrlValidator).validate(unsafeUri);
        // AD-4/DELTA-01: una URI primaria rechazada por SSRF se trata como ausente — cascada
        // normal al catálogo de elegibles (fuente fallback).
        when(tenantSsoConfigPort.resolveEligibleClients(TENANT)).thenReturn(TenantSsoCatalog.empty());

        var resolver = new RegisteredClientBackchannelLogoutUriResolver(
                registeredClientRepository, tenantSsoConfigPort, safeUrlValidator);

        Optional<String> result = resolver.resolve(TENANT, CLIENT_ID);

        assertThat(result).isEmpty();
    }

    @Test
    void resolve_withSsrfRejectedEligibleCatalogUri_returnsEmpty() {
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getClientSettings()).thenReturn(ClientSettings.builder().build());

        String uri = "http://localhost/backchannel-logout";
        when(tenantSsoConfigPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(java.util.Set.of(SsoEligibleClient.of(CLIENT_ID, uri))));
        doThrow(new SsrfProtectionException("Loopback addresses are not allowed"))
                .when(safeUrlValidator).validate(uri);

        var resolver = new RegisteredClientBackchannelLogoutUriResolver(
                registeredClientRepository, tenantSsoConfigPort, safeUrlValidator);

        Optional<String> result = resolver.resolve(TENANT, CLIENT_ID);

        assertThat(result).isEmpty();
    }

    @Test
    void resolve_withSafeEligibleCatalogUri_returnsUri() {
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getClientSettings()).thenReturn(ClientSettings.builder().build());

        String uri = "https://callee.example.com/backchannel-logout";
        when(tenantSsoConfigPort.resolveEligibleClients(TENANT))
                .thenReturn(TenantSsoCatalog.of(java.util.Set.of(SsoEligibleClient.of(CLIENT_ID, uri))));

        var resolver = new RegisteredClientBackchannelLogoutUriResolver(
                registeredClientRepository, tenantSsoConfigPort, safeUrlValidator);

        Optional<String> result = resolver.resolve(TENANT, CLIENT_ID);

        assertThat(result).contains(uri);
    }
}