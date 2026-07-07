package es.in2.vcverifier.sso.infrastructure.adapter;

import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.BackchannelLogoutUriPort;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_BACKCHANNEL_LOGOUT_URI;

/**
 * US-06 (AD-4/DELTA-01): resuelve {@code backchannel_logout_uri} en cascada.
 * Fuente primaria: {@code ClientSettings} del {@link RegisteredClient} (metadata OIDC del cliente).
 * Fuente fallback: catálogo de elegibles del tenant ({@link SsoEligibleClient}, US-05).
 * Si ninguna fuente lo declara, el callee se trata como sin canal (AC-04, backchannel_skipped).
 */
@Component
@RequiredArgsConstructor
public class RegisteredClientBackchannelLogoutUriResolver implements BackchannelLogoutUriPort {

    private final RegisteredClientRepository registeredClientRepository;
    private final TenantSsoConfigPort tenantSsoConfigPort;

    @Override
    public Optional<String> resolve(String tenant, String clientId) {
        Optional<String> primary = resolveFromClientSettings(clientId);
        if (primary.isPresent()) {
            return primary;
        }
        return resolveFromEligibleCatalog(tenant, clientId);
    }

    private Optional<String> resolveFromClientSettings(String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            return Optional.empty();
        }
        String uri = registeredClient.getClientSettings().getSetting(CLIENT_SETTING_BACKCHANNEL_LOGOUT_URI);
        return (uri != null && !uri.isBlank()) ? Optional.of(uri) : Optional.empty();
    }

    private Optional<String> resolveFromEligibleCatalog(String tenant, String clientId) {
        TenantSsoCatalog catalog = tenantSsoConfigPort.resolveEligibleClients(tenant);
        return catalog.findByClientId(clientId)
                .map(SsoEligibleClient::backchannelLogoutUri)
                .filter(uri -> uri != null && !uri.isBlank());
    }
}
