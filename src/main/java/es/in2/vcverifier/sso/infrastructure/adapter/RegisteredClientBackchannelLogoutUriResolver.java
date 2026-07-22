package es.in2.vcverifier.sso.infrastructure.adapter;

import es.in2.vcverifier.shared.domain.exception.SsrfProtectionException;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.BackchannelLogoutUriPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
 * <p>
 * [B3] SEC-14: cualquier URI candidata (de cualquiera de las dos fuentes) se valida con
 * {@link SafeUrlValidator} antes de devolverse — rechaza esquemas distintos de HTTPS y rangos
 * privados/loopback/link-local/metadata de nube. Una URI que no pasa la validación se trata
 * exactamente igual que una ausente (skip, {@code backchannel_skipped}): nunca se propaga la
 * excepción, que rompería el dispatch para el resto de callees de la misma sesión.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RegisteredClientBackchannelLogoutUriResolver implements BackchannelLogoutUriPort {

    private final RegisteredClientRepository registeredClientRepository;
    private final TenantSsoConfigPort tenantSsoConfigPort;
    private final SafeUrlValidator safeUrlValidator;

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
        return validateOrReject(clientId, uri);
    }

    private Optional<String> resolveFromEligibleCatalog(String tenant, String clientId) {
        TenantSsoCatalog catalog = tenantSsoConfigPort.resolveEligibleClients(tenant);
        String uri = catalog.findByClientId(clientId)
                .map(SsoEligibleClient::backchannelLogoutUri)
                .orElse(null);
        return validateOrReject(clientId, uri);
    }

    private Optional<String> validateOrReject(String clientId, String uri) {
        if (uri == null || uri.isBlank()) {
            return Optional.empty();
        }
        try {
            safeUrlValidator.validate(uri);
            return Optional.of(uri);
        } catch (SsrfProtectionException e) {
            log.warn("backchannel_logout_uri_rejected clientId={} reason={}", clientId, e.getMessage());
            return Optional.empty();
        }
    }
}
