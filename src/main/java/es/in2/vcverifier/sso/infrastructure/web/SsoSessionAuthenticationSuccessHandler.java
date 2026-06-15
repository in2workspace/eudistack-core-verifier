package es.in2.vcverifier.sso.infrastructure.web;


import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class SsoSessionAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthenticationSuccessHandler oid4vpSuccessHandler;
    private final EstablishSsoSessionWorkflow establishSsoSessionWorkflow;
    private final SsoSessionCookieFactory cookieFactory;
    private final SsoAuditPort auditPort;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        // 1. mantener flujo OID4VP intacto
        oid4vpSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        // 2. extraer VP data
        VpData vpData = extractVpData(authentication);

        String correlationId = UUID.randomUUID().toString();

        // 3. command correcto
        var command = new SsoSessionCommand(
                vpData.tenant(),
                vpData.holderHash(),
                vpData.clientId(),
                correlationId
        );

        var sessionDescriptor = establishSsoSessionWorkflow.execute(command);

        // 4. cookie
        ResponseCookie cookie = cookieFactory.createCookie(
                vpData.tenantSlug(),
                vpData.tenantRootDomain(),
                Duration.between(java.time.Instant.now(), sessionDescriptor.expiresAt()),
                sessionDescriptor.value()
        );

        response.addHeader("Set-Cookie", cookie.toString());

        // 5. audit seguro
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