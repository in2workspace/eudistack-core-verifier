package es.in2.vcverifier.verifier.domain.model.dispatch;

public enum DispatchReason {
    BY_TYPE,
    BY_CONTEXT,
    BY_TYPE_CONTEXT_MISMATCH,
    ONLY_GENERIC_TYPES,
    MISSING_TYPE_AND_CONTEXT,
    UNKNOWN_CREDENTIAL_TYPE,
    LEGACY_SUNSET_CLOSED,
    BUMPED_DISABLED,
    PROFILE_NOT_FOUND
}
