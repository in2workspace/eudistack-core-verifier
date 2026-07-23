package es.in2.vcverifier.sso.domain.port;

import java.util.Optional;

/**
 * Puerto de dominio (US-06, AD-4/DELTA-01) para resolver el {@code backchannel_logout_uri}
 * declarado por un RP. Dos fuentes posibles (resolución en cascada, responsabilidad del
 * adapter): {@code ClientSettings} (primaria, metadata OIDC del cliente) y el catálogo de
 * elegibles del tenant (fallback, {@code SsoEligibleClient}). Si ninguna fuente lo declara,
 * el callee se trata como sin canal (skip, {@code backchannel_skipped}, AC-04).
 */
public interface BackchannelLogoutUriPort {

    Optional<String> resolve(String tenant, String clientId);
}
