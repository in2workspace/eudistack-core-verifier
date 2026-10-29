package es.in2.vcverifier.shared.infrastructure.audit;

import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.port.AuditTrailPort;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

/**
 * The audit trail while the publisher is off: it records nothing and runs every action untouched, so the
 * use cases behave the same with auditing on or off.
 */
@Component
@ConditionalOnBooleanProperty(name = "auditoria.publisher.enabled", havingValue = false, matchIfMissing = true)
public class NoOpAuditTrailAdapter implements AuditTrailPort {

    @Override
    public void stage(AuditEntry entry) {
        // Nothing to record while the publisher is off.
    }

    @Override
    public void stageInNewTransaction(AuditEntry entry) {
        // Nothing to record while the publisher is off.
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
