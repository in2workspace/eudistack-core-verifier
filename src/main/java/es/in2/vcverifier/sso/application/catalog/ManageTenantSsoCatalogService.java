package es.in2.vcverifier.sso.application.catalog;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

@Service
public class ManageTenantSsoCatalogService {

    private static final Logger log = LoggerFactory.getLogger(ManageTenantSsoCatalogService.class);

    private final SsoCatalogRepositoryPort catalogRepository;
    private final SsoAuditPort auditPort;
    private final Clock clock;

    public ManageTenantSsoCatalogService(
            SsoCatalogRepositoryPort catalogRepository,
            SsoAuditPort auditPort,
            Clock clock
    ) {
        this.catalogRepository = catalogRepository;
        this.auditPort = auditPort;
        this.clock = clock;
    }

    /**
     * Lista los client_id registrados en el catálogo SSO del tenant.
     */
    public List<String> listEligibleClients(String tenant) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        return catalogRepository.listClients(tenant).stream()
                .map(SsoEligibleClient::clientId)
                .toList();
    }

    /**
     * Añade un cliente al catálogo SSO del tenant.
     * Idempotente: si el cliente ya existe no duplica (EC-04).
     */
    public void addEligibleClient(AddEligibleClientCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        SsoEligibleClient client = SsoEligibleClient.of(command.clientId());

        boolean added = catalogRepository.addIfAbsent(command.tenant(), client);

        Instant now = Instant.now(clock);

        if (added) {
            log.info("event=sso_catalog_client_added tenant={} clientId={}", command.tenant(), client.clientId());
            auditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED)
                    .tenant(command.tenant())
                    .clientId(client.clientId())
                    .outcome("ADDED")
                    .occurredAt(now)
                    .build());
        } else {
            log.debug("event=sso_catalog_no_op op=add tenant={} clientId={}", command.tenant(), client.clientId());
            auditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.SSO_CATALOG_NO_OP)
                    .tenant(command.tenant())
                    .clientId(client.clientId())
                    .outcome("ALREADY_EXISTS")
                    .occurredAt(now)
                    .build());
        }
    }

    /**
     * Elimina un cliente del catálogo SSO del tenant.
     * Idempotente: si el cliente no existe no falla.
     */
    public void removeEligibleClient(RemoveEligibleClientCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        SsoEligibleClient client = SsoEligibleClient.of(command.clientId());

        boolean removed = catalogRepository.removeIfPresent(command.tenant(), client);

        Instant now = Instant.now(clock);

        if (removed) {
            log.info("event=sso_catalog_client_removed tenant={} clientId={}", command.tenant(), client.clientId());
            auditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_REMOVED)
                    .tenant(command.tenant())
                    .clientId(client.clientId())
                    .outcome("REMOVED")
                    .occurredAt(now)
                    .build());
        } else {
            log.debug("event=sso_catalog_no_op op=remove tenant={} clientId={}", command.tenant(), client.clientId());
            auditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.SSO_CATALOG_NO_OP)
                    .tenant(command.tenant())
                    .clientId(client.clientId())
                    .outcome("NOT_FOUND")
                    .occurredAt(now)
                    .build());
        }
    }
}
