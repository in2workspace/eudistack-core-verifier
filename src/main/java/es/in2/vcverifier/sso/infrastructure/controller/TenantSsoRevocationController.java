package es.in2.vcverifier.sso.infrastructure.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.sso.application.command.RevokeTenantSessionsCommand;
import es.in2.vcverifier.sso.application.workflow.RevokeTenantSessionsWorkflow;
import es.in2.vcverifier.sso.domain.exception.TenantRevocationException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/tenant/sso")
@RequiredArgsConstructor
public class TenantSsoRevocationController {

    private final RevokeTenantSessionsWorkflow revokeWorkflow;

    @PostMapping("/revoke")
    public ResponseEntity<TenantSsoRevokeResponse> revoke(
            HttpServletRequest request,
            Authentication authentication,
            @RequestHeader(value = "X-Correlation-Id", required = false) String correlationId) {

        String tenant = resolveAndValidateTenant(request, authentication);
        String corrId = (correlationId != null && !correlationId.isBlank())
                ? correlationId
                : UUID.randomUUID().toString();

        int countRevoked = revokeWorkflow.execute(new RevokeTenantSessionsCommand(tenant, corrId));
        return ResponseEntity.ok(new TenantSsoRevokeResponse(countRevoked));
    }

    @ExceptionHandler(TenantRevocationException.class)
    public ResponseEntity<ProblemDetail> handleRevocationFailure(TenantRevocationException ex) {
        log.error("event=sso_emergency_revoke_failed correlation_id={}", ex.getCorrelationId());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ProblemDetail.forStatusAndDetail(
                        HttpStatus.INTERNAL_SERVER_ERROR, "SSO emergency revoke failed"));
    }

    // ─── helpers ──────────

    /**
     * If the Authentication does not carry a tenant, access is denied with 403 (fail-closed).
     *
     * @throws ResponseStatusException 403 if the Authentication carries no tenant
     * @throws ResponseStatusException 403 if the Authentication tenant differs from the X-Tenant-Id header
     */
    private String resolveAndValidateTenant(HttpServletRequest request, Authentication authentication) {
        String authTenant = extractAuthenticatedTenant(authentication);
        if (authTenant == null) {
            log.warn("event=sso_revoke_tenant_missing_in_auth principal={}",
                    authentication != null ? authentication.getClass().getSimpleName() : "null");
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Tenant context not available in authentication");
        }

        String requestTenant = TenantDomainFilter.getCurrentTenant(request);
        if (requestTenant != null && !authTenant.equalsIgnoreCase(requestTenant)) {
            log.warn("event=sso_revoke_cross_tenant_blocked authTenant={} requestTenant={}",
                    authTenant, requestTenant);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cross-tenant access denied");
        }

        return authTenant;
    }

    private static String extractAuthenticatedTenant(Authentication authentication) {
        if (authentication == null) return null;

        if (authentication.getPrincipal() instanceof Map<?, ?> map
                && map.get("tenant") instanceof String t) {
            return t;
        }
        if (authentication.getDetails() instanceof Map<?, ?> map
                && map.get("tenant") instanceof String t) {
            return t;
        }
        return null;
    }

    // ─── DTO ──────────

    public record TenantSsoRevokeResponse(
            @JsonProperty("count_revoked") int countRevoked
    ) {}
}
