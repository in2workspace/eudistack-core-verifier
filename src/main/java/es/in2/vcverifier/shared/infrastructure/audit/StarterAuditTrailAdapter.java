package es.in2.vcverifier.shared.infrastructure.audit;

import com.eudistack.auditoria.application.AuditPublisher;
import com.eudistack.auditoria.context.AuditContextScope;
import com.eudistack.auditoria.context.AuditContexts;
import com.eudistack.auditoria.domain.AuditDraft;
import com.eudistack.auditoria.domain.AuditFact;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.port.AuditTrailPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.function.Supplier;

import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW;

/**
 * Hands the entries of the use cases to the audit outbox starter. {@code stage} joins the transaction that
 * is already active; the other staging method opens one of its own, since the starter never does (EC-09).
 */
@Slf4j
@Component
@ConditionalOnBooleanProperty("auditoria.publisher.enabled")
public class StarterAuditTrailAdapter implements AuditTrailPort {

    private final AuditPublisher publisher;
    private final TransactionTemplate ownTransaction;

    public StarterAuditTrailAdapter(AuditPublisher publisher, PlatformTransactionManager transactionManager) {
        this.publisher = publisher;
        this.ownTransaction = new TransactionTemplate(transactionManager);
        this.ownTransaction.setPropagationBehavior(PROPAGATION_REQUIRES_NEW);
    }

    @Override
    public void stage(AuditEntry entry) {
        try {
            publisher.stage(draftOf(entry));
        } catch (RuntimeException error) {
            reportFailure(entry, error);
            throw error;
        }
    }

    @Override
    public void stageInNewTransaction(AuditEntry entry) {
        try {
            ownTransaction.executeWithoutResult(_ -> publisher.stage(draftOf(entry)));
        } catch (RuntimeException error) {
            reportFailure(entry, error);
            throw error;
        }
    }

    @Override
    public void runWithCorrelationId(String correlationId, Runnable action) {
        try (AuditContextScope _ = AuditContexts.withCorrelationId(correlationId)) {
            action.run();
        }
    }

    @Override
    public <T> T asSystem(String tenant, String actorId, Supplier<T> action) {
        try (AuditContextScope _ = AuditContexts.system(tenant, actorId)) {
            return action.get();
        }
    }

    private static AuditDraft draftOf(AuditEntry entry) {
        AuditFact fact = AuditFact.builder(entry.type().catalogName())
                .action(entry.type().action())
                .resource(entry.resource())
                .details(entry.details())
                .build();
        return switch (entry.result()) {
            case SUCCESS -> AuditDraft.success(fact);
            case DENIED -> AuditDraft.denied(fact, entry.reason());
            case FAILURE -> AuditDraft.failure(fact, entry.reason());
        };
    }

    /** Only the type and the kind of error are logged: the entry carries personal data. */
    private static void reportFailure(AuditEntry entry, RuntimeException error) {
        log.warn("action=stageAuditEvent status=failed eventType={} error={}",
                entry.type().catalogName(), error.getClass().getSimpleName());
    }
}
