package es.in2.vcverifier.sso.infrastructure.web;


import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Lazy;
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

    private final AuthenticationSuccessHandler oid4vpSuccessHandler;
    private final EstablishSsoSessionWorkflow establishSsoSessionWorkflow;
    private final SsoSessionCookieFactory cookieFactory;
    private final SsoAuditPort auditPort;


    public SsoSessionAuthenticationSuccessHandler(
            @Lazy AuthenticationSuccessHandler oid4vpSuccessHandler,
            EstablishSsoSessionWorkflow establishSsoSessionWorkflow,
            SsoSessionCookieFactory cookieFactory,
            SsoAuditPort auditPort
    ) {
        this.oid4vpSuccessHandler = oid4vpSuccessHandler;
        this.establishSsoSessionWorkflow = establishSsoSessionWorkflow;
        this.cookieFactory = cookieFactory;
        this.auditPort = auditPort;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        // 1. Mantener flujo OID4VP intacto, manteniendo la compatibilidad con el login externo.
        oid4vpSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        // 2. Extrae los datos del usuario autenticado (tenant, holderHash, clientId, rootDomain, ...)
        VpData vpData = extractVpData(authentication);

        String correlationId = UUID.randomUUID().toString();

        // 3. Crea sesión interna, valida el tenant, persiste en BD, define tiempo de expiración.
        var command = new SsoSessionCommand(
                vpData.tenant(),
                vpData.holderHash(),
                vpData.clientId(),
                correlationId
        );

        try {
            var sessionDescriptor = establishSsoSessionWorkflow.execute(command);

            if (sessionDescriptor == null) {
                throw new IllegalStateException("Session descriptor is null");
            }

            ResponseCookie cookie = cookieFactory.createCookie(
                    vpData.tenantSlug(),
                    vpData.tenantRootDomain(),
                    Duration.between(java.time.Instant.now(), sessionDescriptor.expiresAt()),
                    sessionDescriptor.value()
            );

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

        } catch (EstablishSsoSessionWorkflow.SsoConfigInconsistentException e) {

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

        } catch (Exception e) {

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


    }

    private VpData extractVpData(Authentication authentication) {

        Object principal = authentication.getPrincipal();

        if (principal instanceof Map<?, ?> map) {
            return new VpData(
                    (String) map.get("tenant"),
                    (String) map.get("holderHash"),
                    (String) map.get("clientId"),
                    (String) (map.get("tenantSlug") != null ? map.get("tenantSlug") : map.get("tenant")),
                    (String) (map.get("tenantRootDomain") != null ? map.get("tenantRootDomain") : "")
            );
        }

        Object details = authentication.getDetails();

        if (details instanceof Map<?, ?> map) {
            return new VpData(
                    (String) map.get("tenant"),
                    (String) map.get("holderHash"),
                    (String) map.get("clientId"),
                    (String) (map.get("tenantSlug") != null ? map.get("tenantSlug") : map.get("tenant")),
                    (String) (map.get("tenantRootDomain") != null ? map.get("tenantRootDomain") : "")
            );
        }

        return new VpData(
                authentication.getName(),
                "",
                authentication.getName(),
                authentication.getName(),
                ""
        );
    }

    private record VpData(
            String tenant,
            String holderHash,
            String clientId,
            String tenantSlug,
            String tenantRootDomain
    ) {}
}