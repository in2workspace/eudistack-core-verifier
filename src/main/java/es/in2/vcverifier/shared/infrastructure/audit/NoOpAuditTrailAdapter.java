package es.in2.vcverifier.shared.infrastructure.audit;

import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.port.AuditTrailPort;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

/**
 * Stand-in for the audit trail until the audit outbox starter is available: it records nothing and runs
 * every action untouched, so wiring the use cases to the port changes no behaviour. The adapter that stages
 * entries in the outbox replaces it.
 */
@Component
public class NoOpAuditTrailAdapter implements AuditTrailPort {

    @Override
    public void stage(AuditEntry entry) {
        // Nothing to record until the outbox adapter replaces this one.
    }

    @Override
    public void stageInNewTransaction(AuditEntry entry) {
        // Nothing to record until the outbox adapter replaces this one.
    }

    @Override
    public void runWithCorrelationId(String correlationId, Runnable action) {
        action.run();
    }

    @Override
    public <T> T asSystem(String tenant, String actorId, Supplier<T> action) {
        return action.get();
    }
}
