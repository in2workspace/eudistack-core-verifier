package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.sso.application.command.RevokeTenantSessionsCommand;
import es.in2.vcverifier.sso.domain.exception.SsoSessionRepositoryException;
import es.in2.vcverifier.sso.domain.exception.TenantRevocationException;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

@Service
public class RevokeTenantSessionsWorkflow {

    private static final Logger log = LoggerFactory.getLogger(RevokeTenantSessionsWorkflow.class);

    private static final String OUTCOME_SUCCESS = "success";
    private static final String OUTCOME_FAILURE = "failure";

    private final SsoSessionRepositoryPort sessionRepositoryPort;
    private final SsoAuditPort auditPort;
    private final Clock clock;

    public RevokeTenantSessionsWorkflow(
            SsoSessionRepositoryPort sessionRepositoryPort,
            SsoAuditPort auditPort,
            Clock clock
    ) {
        this.sessionRepositoryPort = sessionRepositoryPort;
        this.auditPort = auditPort;
        this.clock = clock;
    }

    /**
     * Executes the emergency cut.
     *
     * @param command tenant (derived from the admin principal) + correlationId
     * @return number of revoked sessions ({@code count_revoked})
     * @throws TenantRevocationException if the database revocation fails (rollback applied)
     */
    public int execute(RevokeTenantSessionsCommand command) {

        Objects.requireNonNull(command);

        try {
            int countRevoked = sessionRepositoryPort.revokeAllByTenant(command.tenantId());

            publishAudit(command, countRevoked, OUTCOME_SUCCESS);

            log.info("event=sso_emergency_revoke tenant={} count_revoked={} correlation_id={} outcome={}",
                    command.tenantId(), countRevoked, command.correlationId(), OUTCOME_SUCCESS);

            return countRevoked;

        } catch (SsoSessionRepositoryException ex) {

            publishAudit(command, 0, OUTCOME_FAILURE);

            log.error("event=sso_emergency_revoke tenant={} correlation_id={} outcome={}",
                    command.tenantId(), command.correlationId(), OUTCOME_FAILURE, ex);

            throw new TenantRevocationException(
                    "Failed to revoke SSO sessions for tenant " + command.tenantId(),
                    ex,
                    command.correlationId());
        }
    }

    private void publishAudit(RevokeTenantSessionsCommand command, int countRevoked, String outcome) {
        auditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.EMERGENCY_REVOKE)
                .tenant(command.tenantId())
                .outcome(outcome)
                .correlationId(command.correlationId())
                .occurredAt(Instant.now(clock))
                .countRevoked(countRevoked)
                .build());
    }

}
