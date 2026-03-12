package es.in2.vcverifier.verifier.domain.service;

/**
 * Strategy port for verifying credential revocation status.
 * Each implementation handles a specific status list format
 * (e.g., BitstringStatusListEntry, TokenStatusListEntry).
 */
public interface CredentialStatusVerifier {

    /**
     * Returns whether this verifier supports the given credential status type.
     */
    boolean supports(String credentialStatusType);

    /**
     * Checks whether the credential at the given index in the status list is revoked.
     *
     * @param statusListUrl the URL to fetch the status list credential
     * @param statusIndex   the index within the status list
     * @param expectedPurpose the expected status purpose (e.g., "revocation")
     * @return true if the credential is revoked, false otherwise
     */
    boolean isRevoked(String statusListUrl, String statusIndex, String expectedPurpose);
}
