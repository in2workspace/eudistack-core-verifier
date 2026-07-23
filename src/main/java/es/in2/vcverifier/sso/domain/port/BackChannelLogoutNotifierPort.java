package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.DeliveryOutcome;
import es.in2.vcverifier.sso.domain.model.LogoutTarget;
import es.in2.vcverifier.sso.domain.model.LogoutToken;

/**
 * Puerto de dominio (US-06) para notificar el cierre de sesión a un aplicativo callee
 * vía OIDC Back-Channel Logout 1.0. La resiliencia (retry, circuit breaker, timeout) y el
 * transporte HTTP son responsabilidad exclusiva del adapter de infraestructura
 * ({@code BackChannelLogoutDispatcher}); el dominio solo conoce el resultado final.
 */
public interface BackChannelLogoutNotifierPort {

    /**
     * Notifica el cierre de sesión al callee indicado.
     *
     * @param target destino del callee (client_id + backchannel_logout_uri declarado)
     * @param token  claims del logout_token a entregar (la firma la aplica el adapter)
     * @return el resultado final de la entrega (tras agotar la resiliencia del adapter)
     */
    DeliveryOutcome notifyLogout(LogoutTarget target, LogoutToken token);
}