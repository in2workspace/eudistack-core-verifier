package es.in2.vcverifier.sso.infrastructure.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.catalog.AddEligibleClientCommand;
import es.in2.vcverifier.sso.application.catalog.ManageTenantSsoCatalogService;
import es.in2.vcverifier.sso.application.catalog.RemoveEligibleClientCommand;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

/**
 * Endpoints de administración del catálogo SSO de un tenant.
 * AD-3: protegidos por el SecurityFilterChain de sesión existente (anyRequest().authenticated()).
 * ES-03 / NFR-S-02: el tenant se deriva del contexto de la petición (hostname o cabecera
 * X-Tenant-Id), nunca de un parámetro libre del cuerpo de la petición.
 */
@Slf4j
@Validated
@RestController
@RequestMapping("/tenant/sso/eligible-clients")
@RequiredArgsConstructor
public class TenantSsoCatalogAdminController {

    private final ManageTenantSsoCatalogService catalogService;
    private final TenantSsoConfigPort configPort;

    /** Lista los client_ids del catálogo SSO del tenant autenticado. */
    @GetMapping
    public ResponseEntity<EligibleClientsResponse> listEligibleClients(
            HttpServletRequest request,
            Authentication authentication) {

        String tenant = resolveAndValidateTenant(request, authentication);

        List<String> clients = configPort.getByTenant(tenant)
                .map(TenantSsoConfig::eligibleClientIds)
                .orElse(List.of());

        return ResponseEntity.ok(new EligibleClientsResponse(clients));
    }

    /** Alta idempotente de un client_id en el catálogo SSO del tenant. */
    @PostMapping
    public ResponseEntity<Void> addEligibleClient(
            @RequestBody @Valid AddClientRequest body,
            HttpServletRequest request,
            Authentication authentication) {

        String tenant = resolveAndValidateTenant(request, authentication);
        catalogService.addEligibleClient(new AddEligibleClientCommand(tenant, body.clientId()));
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /** Baja idempotente de un client_id del catálogo SSO del tenant. */
    @DeleteMapping("/{clientId}")
    public ResponseEntity<Void> removeEligibleClient(
            @PathVariable @NotBlank String clientId,
            HttpServletRequest request,
            Authentication authentication) {

        String tenant = resolveAndValidateTenant(request, authentication);
        catalogService.removeEligibleClient(new RemoveEligibleClientCommand(tenant, clientId));
        return ResponseEntity.noContent().build();
    }

    // ─── helpers ─────────────────────────────────────────────────────────────

    /**
     * ES-03: resuelve el tenant desde el atributo de request (hostname / X-Tenant-Id header)
     * y verifica que no haya intento cross-tenant cuando el Authentication transporta tenant.
     *
     * @throws ResponseStatusException 401 si no hay contexto de tenant
     * @throws ResponseStatusException 403 si el tenant del Authentication difiere del request
     */
    private String resolveAndValidateTenant(HttpServletRequest request, Authentication authentication) {
        String requestTenant = TenantDomainFilter.getCurrentTenant(request);
        if (requestTenant == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No tenant context resolved");
        }

        String authTenant = extractAuthenticatedTenant(authentication);
        if (authTenant != null && !authTenant.equalsIgnoreCase(requestTenant)) {
            log.warn("event=sso_catalog_cross_tenant_blocked authTenant={} requestTenant={}",
                    authTenant, requestTenant);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cross-tenant access denied");
        }

        return requestTenant;
    }

    /**
     * Extrae el tenant del Authentication cuando el principal o los details lo transportan
     * (patrón establecido por SsoSessionAuthenticationSuccessHandler).
     * Devuelve null si el Authentication es de tipo usuario/contraseña sin tenant embebido.
     */
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

    // ─── DTOs de request / response ──────────────────────────────────────────

    public record AddClientRequest(
            @JsonProperty("client_id") @NotBlank String clientId
    ) {}

    public record EligibleClientsResponse(
            @JsonProperty("eligible_clients") List<String> eligibleClients
    ) {}
}
