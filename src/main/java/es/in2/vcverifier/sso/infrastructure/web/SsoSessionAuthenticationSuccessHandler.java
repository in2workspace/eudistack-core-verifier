package es.in2.vcverifier.sso.infrastructure.web;


import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class SsoSessionAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final EstablishSsoSessionWorkflow establishSsoSessionWorkflow;
    private final SsoSessionCookieFactory cookieFactory;
    private final TenantSsoConfigPort tenantSsoConfigPort;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        VpData vpData = extractVpData(authentication);
        String correlationId = UUID.randomUUID().toString();

        var command = new SsoSessionCommand(
                vpData.tenant(),
                vpData.holderHash(),
                vpData.clientId(),
                correlationId
        );

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor sessionDescriptor;
        try {
            sessionDescriptor = establishSsoSessionWorkflow.execute(command);
        } catch (EstablishSsoSessionWorkflow.SsoConfigInconsistentException e) {
            // Tenant has SSO disabled (legacy mode) — no cookie, flow continues normally
            log.debug("SSO disabled for tenant '{}', skipping session establishment", vpData.tenant());
            return;
        }

        if (sessionDescriptor == null) {
            // Fail-closed: persistence failure already audited inside the workflow
            log.warn("SSO session could not be persisted for tenant '{}', skipping Set-Cookie", vpData.tenant());
            return;
        }

        String rootDomain = tenantSsoConfigPort.getByTenant(vpData.tenant())
                .map(TenantSsoConfig::rootDomain)
                .orElse("");

        ResponseCookie cookie = cookieFactory.createCookie(
                vpData.tenantSlug(),
                rootDomain,
                Duration.between(Instant.now(), sessionDescriptor.expiresAt()),
                sessionDescriptor.value()
        );

        response.addHeader("Set-Cookie", cookie.toString());
        // Audit is published inside EstablishSsoSessionWorkflow.execute() on success — no duplicate emit here
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