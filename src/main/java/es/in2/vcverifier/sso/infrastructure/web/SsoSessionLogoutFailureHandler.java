package es.in2.vcverifier.sso.infrastructure.web;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

/**
 * US-06 (Single Logout, ES-01): se invoca cuando la validación estándar de
 * {@code id_token_hint}/{@code post_logout_redirect_uri} (Spring AS
 * {@code OidcLogoutAuthenticationProvider}) falla ANTES de llegar a
 * {@link SsoSessionLogoutHandler}. Emite {@code sso_logout_rejected} sin invalidar ni
 * notificar nada (la sesión SSO, si existe, permanece intacta) y delega siempre al
 * comportamiento de error estándar ({@link OAuth2ErrorAuthenticationFailureHandler}).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SsoSessionLogoutFailureHandler implements AuthenticationFailureHandler {

    private final SsoAuditPort auditPort;
    private final AuthenticationFailureHandler delegate = new OAuth2ErrorAuthenticationFailureHandler();

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {

        try {
            String tenant = TenantDomainFilter.getCurrentTenant(request);
            String clientId = request.getParameter("client_id");

            auditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.SSO_LOGOUT_REJECTED)
                    .tenant(tenant)
                    .clientId(clientId)
                    .outcome("rejected")
                    .reason(mapReason(exception))
                    .correlationId(UUID.randomUUID().toString())
                    .occurredAt(Instant.now())
                    .build());
        } catch (Exception e) {
            log.warn("sso_logout_rejected_audit_error: {}", e.getMessage(), e);
        }

        delegate.onAuthenticationFailure(request, response, exception);
    }

    /**
     * ES-01 / [W2]: mapea la excepción a un conjunto cerrado de códigos de razón, en lugar de
     * loggear el mensaje crudo de la excepción (que puede incluir fragmentos de parámetros de
     * la petición). {@code OidcLogoutAuthenticationProvider} de Spring AS lanza
     * {@code OAuth2AuthenticationException} con {@code errorCode=invalid_token} para un
     * {@code id_token_hint} ausente/inválido/desconocido, y {@code errorCode=invalid_request}
     * para un {@code post_logout_redirect_uri} no registrado.
     */
    private static String mapReason(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException oAuth2Exception) {
            String errorCode = oAuth2Exception.getError().getErrorCode();
            if (OAuth2ErrorCodes.INVALID_TOKEN.equals(errorCode)) {
                return "invalid_id_token_hint";
            }
            if (OAuth2ErrorCodes.INVALID_REQUEST.equals(errorCode)) {
                return "unregistered_redirect_uri";
            }
        }
        return "logout_request_rejected";
    }
}
