package es.in2.vcverifier.shared.domain.util;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum VerifierErrorTypes {

    RESOURCE_NOT_FOUND("resource_not_found"),
    CREDENTIAL_REVOKED("credential_revoked"),
    CREDENTIAL_EXPIRED("credential_expired"),
    CREDENTIAL_NOT_ACTIVE("credential_not_active"),
    CREDENTIAL_MAPPING_ERROR("credential_mapping_error"),
    ORGANIZATION_MISMATCH("organization_identifier_mismatch"),
    ISSUER_NOT_AUTHORIZED("issuer_not_authorized"),
    INVALID_CREDENTIAL_TYPE("invalid_credential_type"),
    JWT_CLAIM_MISSING("jwt_claim_missing"),
    JWT_VERIFICATION_FAILED("jwt_verification_failed"),
    JWT_PARSING_FAILED("jwt_parsing_failed"),
    INVALID_SCOPE("invalid_scope"),
    INVALID_VP_TOKEN("invalid_vp_token"),
    LOGIN_TIMEOUT("login_timeout"),
    STATUS_LIST_ERROR("status_list_error"),
    SSRF_PROTECTION("ssrf_protection"),
    FAILED_COMMUNICATION("failed_communication");

    private final String code;
}
