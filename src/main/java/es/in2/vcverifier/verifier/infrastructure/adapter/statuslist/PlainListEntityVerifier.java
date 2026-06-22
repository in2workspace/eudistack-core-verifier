package es.in2.vcverifier.verifier.infrastructure.adapter.statuslist;

import es.in2.vcverifier.verifier.domain.service.CredentialStatusVerifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

// Sunset-window adapter for DOME's legacy "PlainListEntity" credentialStatus
// type. During the migration period we accept these credentials as-is and
// trust their state without fetching the remote plain list.
//
// TODO: Decide whether DOME-legacy issuers should migrate their existing
// credentials to "BitstringStatusListEntry" (W3C VCDM 2.0) before sunset
// closes, or whether this adapter should implement a real fetch of the
// plain list (array of { "nonce": "<id>" } entries) and check membership.
// Until that decision is made, this verifier short-circuits to "not
// revoked" so the legacy login flow keeps working end-to-end.
@Slf4j
@Component
public class PlainListEntityVerifier implements CredentialStatusVerifier {

    private static final String SUPPORTED_TYPE = "PlainListEntity";

    @Override
    public boolean supports(String credentialStatusType) {
        return SUPPORTED_TYPE.equals(credentialStatusType);
    }

    @Override
    public boolean isRevoked(String statusListUrl, String statusIndex, String expectedPurpose) {
        log.warn("PlainListEntity revocation check skipped (DOME legacy sunset). "
                        + "Accepting credential as not revoked. URL={}, index={}, purpose={}",
                statusListUrl, statusIndex, expectedPurpose);
        return false;
    }
}
