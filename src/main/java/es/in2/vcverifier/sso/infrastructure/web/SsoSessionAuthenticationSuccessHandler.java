package es.in2.vcverifier.sso.infrastructure.web;


import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.exception.SsoConfigInconsistentException;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@Component
public class SsoSessionAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final EstablishSsoSessionWorkflow establishSsoSessionWorkflow;
    private final SsoSessionCookieFactory cookieFactory;
    private final SsoAuditPort auditPort;
    private final TenantSsoConfigPort tenantSsoConfigPort;


    public SsoSessionAuthenticationSuccessHandler(
            EstablishSsoSessionWorkflow establishSsoSessionWorkflow,
            SsoSessionCookieFactory cookieFactory,
            SsoAuditPort auditPort,
            TenantSsoConfigPort tenantSsoConfigPort
    ) {
        this.establishSsoSessionWorkflow = establishSsoSessionWorkflow;
        this.cookieFactory = cookieFactory;
        this.auditPort = auditPort;
        this.tenantSsoConfigPort = tenantSsoConfigPort;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        // 1. Extrae los datos del usuario autenticado (tenant, holderHash, clientId, ...)
        VpData vpData = extractVpData(authentication);

        String correlationId = UUID.randomUUID().toString();

        // 2. Resuelve rootDomain desde TenantSsoConfigPort en lugar de depender
        // de los detalles de autenticación, que pueden no estar populados
        // (e.g. Oid4vpController.buildSsoAuthentication() no incluye tenantRootDomain).
        String rootDomain = tenantSsoConfigPort.getByTenant(vpData.tenant())
                .map(config -> config.rootDomain() != null ? config.rootDomain() : "")
                .orElse("");

        // 3. Crea sesión interna, valida el tenant, persiste en BD, define tiempo de expiración.
        var command = new SsoSessionCommand(
                vpData.tenant(),
                vpData.holderHash(),
                vpData.clientId(),
                correlationId
        );

        try {
            var sessionDescriptor = establishSsoSessionWorkflow.execute(command);

            // Fail-closed: si el descriptor es null (fallo de persistencia),
            // registramos el fallo pero NO lanzamos excepción para no romper
            // el flujo OID4VP que viene a continuación.
            if (sessionDescriptor == null) {
                auditPort.publish(new SsoAuditEvent(
                        SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED,
                        vpData.tenant(),
                        vpData.clientId(),
                        vpData.holderHash(),
                        "FAILURE",
                        correlationId,
                        java.time.Instant.now()
                ));
            } else {
                ResponseCookie cookie = cookieFactory.createCookie(
                        vpData.tenantSlug(),
                        rootDomain,
                        Duration.between(java.time.Instant.now(), sessionDescriptor.expiresAt()),
                        sessionDescriptor.value()
                );

                // Set-Cookie ANTES de delegar al handler que puede hacer commit del response.
                response.addHeader("Set-Cookie", cookie.toString());

                auditPort.publish(new SsoAuditEvent(
                        SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                        vpData.tenant(),
                        vpData.clientId(),
                        vpData.holderHash(),
                        "SUCCESS",
                        correlationId,
                        java.time.Instant.now()
                ));
            }

        } catch (SsoConfigInconsistentException e) {
            // Tenant legacy o SSO deshabilitado: auditamos pero NO re-lanzamos.
            // El flujo OID4VP debe completar con redirect aunque no haya cookie SSO.
            auditPort.publish(new SsoAuditEvent(
                    SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED,
                    vpData.tenant(),
                    vpData.clientId(),
                    vpData.holderHash(),
                    "FAILURE",
                    correlationId,
                    java.time.Instant.now()
            ));
        } catch (Exception e) {
            // Cualquier otro error inesperado sí se re-lanza.
            auditPort.publish(new SsoAuditEvent(
                    SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED,
                    vpData.tenant(),
                    vpData.clientId(),
                    vpData.holderHash(),
                    "FAILURE",
                    correlationId,
                    java.time.Instant.now()
            ));
            throw e;
        }

        // 4. NO se delega en ningún AuthenticationSuccessHandler que haga commit del response.
        //    El antiguo delegado (SavedRequestAwareAuthenticationSuccessHandler) redirigía a su
        //    defaultTargetUrl "/" → con el context path = "/verifier/", un path que nadie sirve:
        //    el wallet hace fetch(redirect:'follow'), sigue ese 302 y termina en 504/CORS,
        //    incumpliendo EUDISTACK-547 AC-01 (la respuesta debe ir hacia el redirect_uri del
        //    aplicativo) y AC-04 (sin regresión observable del flujo OID4VP).
        //    El redirect al redirect_uri real lo entrega AuthorizationResponseProcessorService
        //    vía SSE; aquí el POST /oid4vp/auth-response mantiene el 200 OK del controller
        //    (@ResponseStatus(HttpStatus.OK)) con la cookie __Secure-sso-* ya añadida en el paso 3.
    }

    private VpData extractVpData(Authentication authentication) {

        Object principal = authentication.getPrincipal();

        if (principal instanceof Map<?, ?> map) {
            return new VpData(
                    (String) map.get("tenant"),
                    (String) map.get("holderHash"),
                    (String) map.get("clientId"),
                    (String) (map.get("tenantSlug") != null ? map.get("tenantSlug") : map.get("tenant"))
            );
        }

        Object details = authentication.getDetails();

        if (details instanceof Map<?, ?> map) {
            return new VpData(
                    (String) map.get("tenant"),
                    (String) map.get("holderHash"),
                    (String) map.get("clientId"),
                    (String) (map.get("tenantSlug") != null ? map.get("tenantSlug") : map.get("tenant"))
            );
        }

        return new VpData(
                authentication.getName(),
                "",
                authentication.getName(),
                authentication.getName()
        );
    }

    private record VpData(
            String tenant,
            String holderHash,
            String clientId,
            String tenantSlug
    ) {}
}