package es.in2.vcverifier.sso.domain.model;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * EUD-252: a cross-device login whose VP was already verified (wallet POST) but whose SSO session
 * has not been established yet. It waits — single use, short-lived — for the browser that started
 * the login to call the close endpoint carrying the matching {@code __Host-sso-tx} cookie.
 *
 * @param tenant             tenant resolved on the wallet POST
 * @param holderSubject      RAW subject of the presented credential (hashed by the establishment
 *                           workflow); {@code null} when the login is not SSO-eligible
 * @param clientId           OAuth2 client that started the login
 * @param credentialJson     verified credential claims (SSO snapshot)
 * @param redirectUrl        {@code redirectUri?code=...&state=...} to deliver on success
 * @param redirectUri        client's registered redirect_uri (target of the error redirect)
 * @param state              OAuth2 state of the login
 * @param browserBindingHash SHA-256 (hex) of the browser-binding cookie set at /authorize
 * @param authorizationCode  issued code, invalidated if the binding check fails
 * @param ssoEligible        whether the close step must also establish the SSO session; when
 *                           {@code false} the binding is still checked, the browser just gets the code
 */
public record PendingSsoLogin(
        String tenant,
        String holderSubject,
        String clientId,
        JsonNode credentialJson,
        String redirectUrl,
        String redirectUri,
        String state,
        String browserBindingHash,
        String authorizationCode,
        boolean ssoEligible
) {

    /** Redacted: the subject, the code and the code-bearing redirect URL must never reach logs. */
    @Override
    public String toString() {
        return "PendingSsoLogin[tenant=" + tenant + ", clientId=" + clientId + ", redirectUri=" + redirectUri + "]";
    }
}
