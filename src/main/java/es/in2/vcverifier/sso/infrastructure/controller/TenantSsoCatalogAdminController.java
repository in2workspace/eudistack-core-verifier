package es.in2.vcverifier.sso.infrastructure.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.sso.application.catalog.AddEligibleClientCommand;
import es.in2.vcverifier.sso.application.catalog.ManageTenantSsoCatalogService;
import es.in2.vcverifier.sso.application.catalog.RemoveEligibleClientCommand;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Endpoint de administración del catálogo SSO por tenant.
 *
 * Seguridad (AD-3): protegido por el SecurityFilterChain de sesión admin.
 * 401 → Spring Security ante ausencia de sesión.
 * 403 → tenant ausente en contexto (ES-03): la solicitud no pasa el filtro de routing.
 *
 * El tenant se extrae siempre de {@link TenantDomainFilter} (hostname / X-Tenant-Id),
 * nunca de un parámetro libre del caller (ES-03, NFR-S-02).
 */
@Slf4j
@RestController
@RequestMapping("/tenant/sso/eligible-clients")
@RequiredArgsConstructor
@Tag(name = "SSO Catalog Admin", description = "Gestión del catálogo de clientes elegibles para reutilización SSO")
public class TenantSsoCatalogAdminController {

    private final ManageTenantSsoCatalogService catalogService;

    // ----------------------------------------------------------------
    // GET  /tenant/sso/eligible-clients
    // ----------------------------------------------------------------

    @Operation(summary = "Listar clientes elegibles SSO del tenant")
    @ApiResponse(responseCode = "200", description = "Lista de client_id registrados")
    @ApiResponse(responseCode = "401", description = "Sin sesión admin activa")
    @ApiResponse(responseCode = "403", description = "Tenant no resolvible desde el contexto autenticado")
    @GetMapping
    public ResponseEntity<EligibleClientsResponse> listEligibleClients(HttpServletRequest request) {
        String tenant = resolveTenantOrReject(request);
        if (tenant == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        List<String> clients = catalogService.listEligibleClients(tenant);
        log.debug("event=sso_catalog_list tenant={} count={}", tenant, clients.size());
        return ResponseEntity.ok(new EligibleClientsResponse(clients));
    }

    // ----------------------------------------------------------------
    // POST /tenant/sso/eligible-clients
    // ----------------------------------------------------------------

    @Operation(summary = "Añadir un cliente al catálogo SSO del tenant (idempotente)")
    @ApiResponse(responseCode = "200", description = "Cliente añadido o ya existente (idempotente)")
    @ApiResponse(responseCode = "400", description = "client_id ausente o inválido")
    @ApiResponse(responseCode = "401", description = "Sin sesión admin activa")
    @ApiResponse(responseCode = "403", description = "Tenant no resolvible desde el contexto autenticado")
    @PostMapping
    public ResponseEntity<Void> addEligibleClient(
            HttpServletRequest request,
            @RequestBody AddEligibleClientRequest body
    ) {
        String tenant = resolveTenantOrReject(request);
        if (tenant == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        catalogService.addEligibleClient(new AddEligibleClientCommand(tenant, body.clientId()));
        return ResponseEntity.ok().build();
    }

    // ----------------------------------------------------------------
    // DELETE /tenant/sso/eligible-clients/{clientId}
    // ----------------------------------------------------------------

    @Operation(summary = "Eliminar un cliente del catálogo SSO del tenant (idempotente)")
    @ApiResponse(responseCode = "204", description = "Cliente eliminado o no existente (idempotente)")
    @ApiResponse(responseCode = "401", description = "Sin sesión admin activa")
    @ApiResponse(responseCode = "403", description = "Tenant no resolvible desde el contexto autenticado")
    @DeleteMapping("/{clientId}")
    public ResponseEntity<Void> removeEligibleClient(
            HttpServletRequest request,
            @PathVariable String clientId
    ) {
        String tenant = resolveTenantOrReject(request);
        if (tenant == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        catalogService.removeEligibleClient(new RemoveEligibleClientCommand(tenant, clientId));
        return ResponseEntity.noContent().build();
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    /**
     * ES-03 / NFR-S-02: el tenant proviene exclusivamente del contexto de routing
     * (hostname o cabecera X-Tenant-Id resuelto por TenantDomainFilter).
     * Devuelve null si el tenant no está presente → el caller devuelve 403.
     */
    private String resolveTenantOrReject(HttpServletRequest request) {
        String tenant = TenantDomainFilter.getCurrentTenant(request);
        if (tenant == null || tenant.isBlank()) {
            log.warn("event=sso_catalog_admin_rejected reason=tenant_missing");
            return null;
        }
        return tenant;
    }

    // ----------------------------------------------------------------
    // Request / Response DTOs
    // ----------------------------------------------------------------

    record AddEligibleClientRequest(
            @JsonProperty("client_id") String clientId
    ) {}

    record EligibleClientsResponse(
            @JsonProperty("eligible_clients") List<String> eligibleClients
    ) {}
}
