package es.in2.vcverifier.shared.domain.port;

import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Test double of {@link AuditTrailPort} that keeps what each flow staged, in order, and in which way, so a
 * test can assert on the entries without a database.
 */
public class RecordingAuditTrail implements AuditTrailPort {

    private final List<AuditEntry> staged = new ArrayList<>();
    private final List<AuditEntry> stagedInNewTransaction = new ArrayList<>();
    private final List<String> correlationIds = new ArrayList<>();
    private final List<String> systemScopes = new ArrayList<>();
    private boolean failOnNewTransaction;

    public RecordingAuditTrail failingOnNewTransaction() {
        this.failOnNewTransaction = true;
        return this;
    }

    @Override
    public void stage(AuditEntry entry) {
        staged.add(entry);
    }

    @Override
    public void stageInNewTransaction(AuditEntry entry) {
        if (failOnNewTransaction) {
            throw new IllegalStateException("outbox unavailable");
        }
        stagedInNewTransaction.add(entry);
    }

    @Override
    public void runWithCorrelationId(String correlationId, Runnable action) {
        correlationIds.add(correlationId);
        action.run();
    }

    @Override
    public <T> T asSystem(String tenant, String actorId, Supplier<T> action) {
        systemScopes.add(tenant + "/" + actorId);
        return action.get();
    }

    public List<AuditEntry> staged() {
        return List.copyOf(staged);
    }

    public List<AuditEntry> stagedInNewTransaction() {
        return List.copyOf(stagedInNewTransaction);
    }

    public List<AuditEntry> all() {
        List<AuditEntry> all = new ArrayList<>(staged);
        all.addAll(stagedInNewTransaction);
        return all;
    }

    public List<String> correlationIds() {
        return List.copyOf(correlationIds);
    }

    /** The {@code tenant/actor} of every background scope opened, in order. */
    public List<String> systemScopes() {
        return List.copyOf(systemScopes);
    }
}
