package es.in2.vcverifier.shared.domain.model.audit;

/**
 * Outcome of an audited fact, as the audit event catalogue defines it: completed, evaluated and refused,
 * or not completable.
 */
public enum AuditResult {
    SUCCESS,
    DENIED,
    FAILURE
}
