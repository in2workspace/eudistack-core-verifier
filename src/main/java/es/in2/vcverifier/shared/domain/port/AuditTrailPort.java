package es.in2.vcverifier.shared.domain.port;

import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;

import java.util.function.Supplier;

/**
 * Output port to the audit trail (EUD-244): the use case states what happened and the adapter hands it to
 * the audit outbox. The domain depends only on this interface, never on the outbox starter.
 *
 * <p>The tenant, actor, organization and correlation id are read from the audit context of the operation,
 * not passed here. The Verifier keeps its state in memory, so most of what it audits has no business write
 * to join and is staged in a transaction of its own.
 */
public interface AuditTrailPort {

    /**
     * Stages the entry in the transaction that is already active, so it commits or rolls back together
     * with the business write it describes. Fails when no transaction is active.
     */
    void stage(AuditEntry entry);

    /** Stages the entry in a short transaction of its own, for a fact that has no business write to join. */
    void stageInNewTransaction(AuditEntry entry);

    /**
     * Stages the entry in a transaction of its own and never fails the caller: for a fact that already
     * happened (a call made, a client authenticated), where a broken audit channel must not undo or hide
     * the operation. The adapter reports the failure itself.
     */
    default void stageBestEffort(AuditEntry entry) {
        try {
            stageInNewTransaction(entry);
        } catch (RuntimeException _) {
            // The adapter has already reported it; the operation goes on.
        }
    }

    /** Runs {@code action} with the given correlation id, which replaces the one of the request. */
    void runWithCorrelationId(String correlationId, Runnable action);

    /** Runs {@code action} with the audit context of a background process acting on {@code tenant}. */
    <T> T asSystem(String tenant, String actorId, Supplier<T> action);
}
