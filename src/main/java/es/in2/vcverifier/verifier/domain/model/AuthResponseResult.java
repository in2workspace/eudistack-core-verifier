package es.in2.vcverifier.verifier.domain.model;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Outcome of a successfully verified OID4VP authorization response (wallet POST).
 *
 * <p>EUD-252: the processor no longer delivers the redirect to the browser itself — the caller
 * decides whether the browser goes straight to {@code redirectUrl} (no SSO) or first through the
 * browser-bound close step that establishes the SSO session in the browser that started the login.
 *
 * @param credentialJson            resolved claims of the verified credential (SSO snapshot source)
 * @param redirectUrl               {@code redirectUri?code=...&state=...} for the relying party
 * @param redirectUri               the client's registered redirect_uri, as validated at /authorize
 * @param state                     OAuth2 state of the login (SSE channel key)
 * @param clientId                  OAuth2 client that started the login
 * @param authorizationCode         the issued code, needed only to invalidate it if the close step
 *                                  fails its browser-binding check — never log it
 * @param browserBindingHash        SHA-256 (hex) of the {@code __Host-sso-tx} cookie set at
 *                                  /authorize, or {@code null} when the login was not bound
 * @param authorizationServerBaseUrl scheme://host[:port]/context-path the browser used at /authorize
 */
public record AuthResponseResult(
        JsonNode credentialJson,
        String redirectUrl,
        String redirectUri,
        String state,
        String clientId,
        String authorizationCode,
        String browserBindingHash,
        String authorizationServerBaseUrl
) {

    /** Redacted: {@code redirectUrl} and {@code authorizationCode} carry the code in clear. */
    @Override
    public String toString() {
        return "AuthResponseResult[clientId=" + clientId + ", redirectUri=" + redirectUri
                + ", bound=" + (browserBindingHash != null) + "]";
    }
}
