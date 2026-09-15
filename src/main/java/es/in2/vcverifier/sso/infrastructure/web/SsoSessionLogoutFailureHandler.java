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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_LOGIN_PAGE_URI;
import static es.in2.vcverifier.shared.domain.util.Constants.SESSION_EXPIRED;

/**
 * US-06 (Single Logout, ES-01): se invoca cuando la validación estándar de
 * {@code id_token_hint}/{@code post_logout_redirect_uri} (Spring AS
 * {@code OidcLogoutAuthenticationProvider}) falla ANTES de llegar a
 * {@link SsoSessionLogoutHandler}. Emite {@code sso_logout_rejected} sin invalidar ni
 * notificar nada (la sesión SSO, si existe, permanece intacta).
 * <p>
 * Si la request identifica un cliente registrado (parámetro {@code client_id}, estándar en
 * OIDC RP-Initiated Logout), intenta redirigir con {@code ?error=session_expired} en vez de
 * exponer el {@link org.springframework.security.oauth2.core.OAuth2Error} como JSON crudo,
 * probando dos destinos en este orden:
 * <ol>
 *   <li>{@code loginPageUri} del cliente — configuración del propio servidor (no viene de la
 *       request), pensada para clientes con su propia UI de login OID4VP (p. ej.
 *       {@code proximity-verifier-pwa}). No hay riesgo de open-redirect: solo {@code client_id}
 *       viene de la request, y únicamente se usa como clave de búsqueda.</li>
 *   <li>El {@code post_logout_redirect_uri} de la request, SOLO cuando coincide exactamente con
 *       uno de los {@code postLogoutRedirectUris} ya registrados para ese cliente. Cubre a los
 *       clientes sin {@code loginPageUri} propia que delegan su login en el {@code mfe-login}
 *       compartido del Verifier (p. ej. el Issuer UI): estos nunca pueden fijar {@code loginPageUri}
 *       sin romper su flujo de login normal (ver {@code CustomAuthorizationRequestConverter}), así
 *       que sin este segundo destino jamás verían el redirect guiado. Acotar el resultado al
 *       allowlist que el propio cliente ya registró evita el open-redirect que supondría confiar
 *       en el {@code post_logout_redirect_uri} de la request sin más — el mismo modelo de
 *       confianza que Spring AS usa para validar ese parámetro en el camino feliz.</li>
 * </ol>
 * Si no hay cliente resuelto o ninguno de los dos destinos es válido, se mantiene el
 * comportamiento estándar ({@link OAuth2ErrorAuthenticationFailureHandler}).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SsoSessionLogoutFailureHandler implements AuthenticationFailureHandler {

    private final SsoAuditPort auditPort;
    private final RegisteredClientRepository registeredClientRepository;
    private final AuthenticationFailureHandler delegate = new OAuth2ErrorAuthenticationFailureHandler();

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {

        String clientId = request.getParameter("client_id");

        try {
            String tenant = TenantDomainFilter.getCurrentTenant(request);

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

        String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");
        String sessionExpiredRedirect = resolveSessionExpiredRedirect(clientId, postLogoutRedirectUri);
        if (sessionExpiredRedirect != null) {
            response.sendRedirect(sessionExpiredRedirect);
            return;
        }

        delegate.onAuthenticationFailure(request, response, exception);
    }

    private String resolveSessionExpiredRedirect(String clientId, String postLogoutRedirectUri) {
        if (clientId == null || clientId.isBlank()) {
            return null;
        }
        try {
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
            if (registeredClient == null) {
                return null;
            }
            String target = resolveLoginPageUri(registeredClient);
            if (target == null) {
                target = resolveRegisteredPostLogoutRedirectUri(registeredClient, postLogoutRedirectUri);
            }
            if (target == null) {
                return null;
            }
            return UriComponentsBuilder.fromHttpUrl(target)
                    .queryParam("error", SESSION_EXPIRED)
                    .build()
                    .toUriString();
        } catch (Exception e) {
            log.warn("sso_logout_session_expired_redirect_error: {}", e.getMessage(), e);
            return null;
        }
    }

    private static String resolveLoginPageUri(RegisteredClient registeredClient) {
        String loginPageUri = registeredClient.getClientSettings().getSetting(CLIENT_SETTING_LOGIN_PAGE_URI);
        // ClientLoaderConfig enforces HTTPS on loginPageUri at registration time, so this is a
        // defensive check, not the primary one: UriComponentsBuilder.fromHttpUrl doesn't reject
        // a schemeless string, it happily builds one, which would turn into a broken
        // sendRedirect() below instead of falling back to the standard error handler.
        return isHttps(loginPageUri) ? loginPageUri : null;
    }

    /**
     * Only trusts {@code postLogoutRedirectUri} when it exactly matches one of the client's own
     * registered {@code postLogoutRedirectUris}. Both {@code client_id} and this value come
     * straight from the (unauthenticated) request, so without this membership check a
     * legitimate-looking {@code client_id} would let a caller redirect anywhere it likes.
     * Unlike {@code loginPageUri}, {@code ClientLoaderConfig} does not enforce HTTPS on
     * {@code postLogoutRedirectUris} at load time — {@link #isHttps} here is the primary check
     * for this path, not a defensive one.
     */
    private static String resolveRegisteredPostLogoutRedirectUri(RegisteredClient registeredClient, String postLogoutRedirectUri) {
        if (postLogoutRedirectUri == null || postLogoutRedirectUri.isBlank()) {
            return null;
        }
        if (!registeredClient.getPostLogoutRedirectUris().contains(postLogoutRedirectUri)) {
            return null;
        }
        return isHttps(postLogoutRedirectUri) ? postLogoutRedirectUri : null;
    }

    private static boolean isHttps(String uri) {
        return uri != null && uri.startsWith("https://");
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
