package es.in2.vcverifier.sso.infrastructure.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.sso.domain.model.SsoTenantMetrics;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/tenant/sso/metrics")
@RequiredArgsConstructor
public class SsoMetricsController {

    private final SsoMetricsPort metricsPort;

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SsoMetricsResponse> getMetrics(
            HttpServletRequest request,
            Authentication authentication) {

        String tenant = resolveAndValidateTenant(request, authentication);
        return ResponseEntity.ok(SsoMetricsResponse.from(metricsPort.metricsFor(tenant)));
    }

    // ─── helpers ─────────────────────────────────────────────────────────────

    private String resolveAndValidateTenant(HttpServletRequest request, Authentication authentication) {
        String authTenant = extractAuthenticatedTenant(authentication);
        if (authTenant == null) {
            log.warn("event=sso_metrics_tenant_missing_in_auth principal={}",
                    authentication != null ? authentication.getClass().getSimpleName() : "null");
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Tenant context not available in authentication");
        }

        String requestTenant = TenantDomainFilter.getCurrentTenant(request);
        if (requestTenant != null && !authTenant.equalsIgnoreCase(requestTenant)) {
            log.warn("event=sso_metrics_cross_tenant_blocked authTenant={} requestTenant={}",
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

    // ─── response DTO ─────────────────────────────────────────────────────────

    public record SsoMetricsResponse(
            @JsonProperty("tenant") String tenant,
            @JsonProperty("established_total") long establishedTotal,
            @JsonProperty("reuse_total") long reuseTotal,
            @JsonProperty("oid4vp_avoided_total") long oid4vpAvoidedTotal,
            @JsonProperty("reuse_ratio") Double reuseRatio,
            @JsonProperty("by_client_id") Map<String, ClientReuse> byClientId
    ) {
        public record ClientReuse(
                @JsonProperty("client_id") String clientId,
                @JsonProperty("reuse_total") long reuseTotal
        ) {}

        static SsoMetricsResponse from(SsoTenantMetrics metrics) {
            Map<String, ClientReuse> byClientId = new LinkedHashMap<>();
            metrics.byClientId().forEach((clientId, m) ->
                    byClientId.put(clientId, new ClientReuse(m.clientId(), m.reuseTotal())));
            return new SsoMetricsResponse(
                    metrics.tenant(),
                    metrics.establishedTotal(),
                    metrics.reuseTotal(),
                    metrics.oid4vpAvoidedTotal(),
                    metrics.reuseRatio(),
                    byClientId);
        }
    }

}
