package es.in2.vcverifier.sso.infrastructure.web;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.TerminateSsoSessionWorkflow;
import es.in2.vcverifier.sso.application.command.TerminateSsoSessionCommand;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.UUID;

/**
 * US-06 (Single Logout, AD-1): enganche del {@code TerminateSsoSessionWorkflow} en el handler
 * estándar {@code GET/POST /oidc/logout} (OIDC RP-Initiated Logout 1.0) de Spring Authorization
 * Server. Decorador — NO reimplementa la validación de {@code id_token_hint}/
 * {@code post_logout_redirect_uri} (ya la hizo {@code OidcLogoutAuthenticationProvider} antes de
 * invocar este handler) ni el redirect final: delega siempre a un
 * {@link OidcLogoutAuthenticationSuccessHandler} fresco tras ejecutar (o no) la lógica SSO.
 * <p>
 * AC-05 / R-1: si no hay cookie SSO para el tenant resuelto (tenant legacy, SSO deshabilitado,
 * o sesión ausente/expirada), el bloque SSO es un no-op por construcción — nunca se invoca el
 * workflow — y el delegate completa el logout estándar exactamente como antes de esta Story.
 * Cualquier excepción inesperada en la lógica SSO se captura y jamás bloquea el delegate.
 */
@Slf4j
@Component
public class SsoSessionLogoutHandler implements AuthenticationSuccessHandler {

    private final TerminateSsoSessionWorkflow terminateSsoSessionWorkflow;
    private final SsoSessionCookieFactory cookieFactory;
    private final TenantSsoConfigPort tenantSsoConfigPort;
    private final SsoSessionRepositoryPort sessionRepositoryPort;
    private final AuthenticationSuccessHandler delegate = new OidcLogoutAuthenticationSuccessHandler();

    public SsoSessionLogoutHandler(
            TerminateSsoSessionWorkflow terminateSsoSessionWorkflow,
            SsoSessionCookieFactory cookieFactory,
            TenantSsoConfigPort tenantSsoConfigPort,
            SsoSessionRepositoryPort sessionRepositoryPort
    ) {
        this.terminateSsoSessionWorkflow = terminateSsoSessionWorkflow;
        this.cookieFactory = cookieFactory;
        this.tenantSsoConfigPort = tenantSsoConfigPort;
        this.sessionRepositoryPort = sessionRepositoryPort;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        try {
            handleSsoLogout(request, response, authentication);
        } catch (Exception e) {
            // AC-05/R-1: un fallo en la lógica SSO NUNCA debe bloquear el logout estándar.
            log.warn("sso_logout_handler_error: {}", e.getMessage(), e);
        }

        delegate.onAuthenticationSuccess(request, response, authentication);
    }

    private void handleSsoLogout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        if (!(authentication instanceof OidcLogoutAuthenticationToken logoutToken)) {
            return;
        }

        String tenant = TenantDomainFilter.getCurrentTenant(request);
        if (tenant == null || tenant.isBlank()) {
            return;
        }

        String cookieName = "__Secure-sso-" + tenant;
        String sessionIdValue = extractCookieValue(request, cookieName);
        if (sessionIdValue == null || sessionIdValue.isBlank()) {
            // AC-05: sin sesión SSO — no-op natural, nada que invalidar ni notificar.
            return;
        }

        String correlationId = UUID.randomUUID().toString();
        SsoSessionId sessionId = SsoSessionId.of(sessionIdValue);

        // AC-06: resuelve holder_hash desde la sesión ANTES de invocar el workflow
        // (mismo patrón que ReuseSsoSessionWorkflowImpl al leer SsoSession.getHolderHash()).
        // Nullable si la sesión ya no está activa (EC-01) — el workflow sigue siendo idempotente.
        String holderHash = sessionRepositoryPort.findActiveById(sessionId, tenant)
                .map(SsoSession::getHolderHash)
                .orElse(null);

        var command = new TerminateSsoSessionCommand(
                tenant,
                sessionId,
                logoutToken.getClientId(),
                correlationId,
                holderHash
        );

        terminateSsoSessionWorkflow.execute(command);

        String rootDomain = tenantSsoConfigPort.getByTenant(tenant)
                .map(config -> config.rootDomain() != null ? config.rootDomain() : "")
                .orElse("");

        ResponseCookie expiredCookie = cookieFactory.createCookie(tenant, rootDomain, Duration.ZERO, "");
        response.addHeader("Set-Cookie", expiredCookie.toString());
    }

    private String extractCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
