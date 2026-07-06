package es.in2.vcverifier.sso.application.catalog;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class ManageTenantSsoCatalogService {

    private final SsoCatalogRepositoryPort catalogRepository;
    private final SsoAuditPort auditPort;
    private final Clock clock;

    /**
     * Añade un cliente al catálogo SSO del tenant.
     * EC-04 idempotente: si el cliente ya existe no duplica y el resultado es el mismo.
     * AC-04 / NFR-O-01: emite evento auditable independientemente del resultado.
     */
    public void addEligibleClient(AddEligibleClientCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        SsoEligibleClient client = SsoEligibleClient.of(command.clientId());
        boolean added = catalogRepository.addClient(command.tenant(), client);
        String outcome = added ? "ADDED" : "ALREADY_PRESENT";

        log.info("event=sso_catalog_add tenant={} clientId={} outcome={}",
                command.tenant(), command.clientId(), outcome);

        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED)
                .tenant(command.tenant())
                .clientId(command.clientId())
                .outcome(outcome)
                .occurredAt(Instant.now(clock))
                .build());
    }

    /**
     * Elimina un cliente del catálogo SSO del tenant.
     * EC-04 idempotente: si el cliente no existe no falla y el resultado es el mismo.
     * AC-04 / NFR-O-01: emite evento auditable independientemente del resultado.
     */
    public void removeEligibleClient(RemoveEligibleClientCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        SsoEligibleClient client = SsoEligibleClient.of(command.clientId());
        boolean removed = catalogRepository.removeClient(command.tenant(), client);
        String outcome = removed ? "REMOVED" : "NOT_FOUND";

        log.info("event=sso_catalog_remove tenant={} clientId={} outcome={}",
                command.tenant(), command.clientId(), outcome);

        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_REMOVED)
                .tenant(command.tenant())
                .clientId(command.clientId())
                .outcome(outcome)
                .occurredAt(Instant.now(clock))
                .build());
    }
}
