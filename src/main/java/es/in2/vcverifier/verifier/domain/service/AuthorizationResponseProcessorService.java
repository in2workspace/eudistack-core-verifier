package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;

import java.util.Set;

public interface AuthorizationResponseProcessorService {

    /**
     * Verifies the wallet's VP and issues the authorization code. Validation failures are still
     * notified to the browser over SSE ({@code validation_failed}) by this method; the success
     * redirect is NOT sent here (EUD-252) — the caller decides where the browser must go.
     *
     * @return the verified credential claims plus everything the caller needs to route the
     * browser: the RP redirect URL, the issued code and the browser-binding hash of the login
     */
    AuthResponseResult handleAuthResponse(String state, String vpToken);

    /**
     * Issues an authorization code directly for an already-authenticated SSO-reused session — no VP
     * is re-presented. Mirrors the code-issuance tail of {@link #handleAuthResponse}, using a
     * credential snapshot captured at the original establishment instead of a freshly-verified VP.
     * The caller MUST have already validated {@code redirectUri} against the client's registered
     * redirect URIs — this method does not repeat that check.
     *
     * @return the redirect URL ({@code redirectUri?code=...&state=...}) to send back to the RP
     */
    String issueCodeForReusedSession(
            String clientId,
            String redirectUri,
            Set<String> scopes,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String nonce,
            JsonNode credentialJson
    );

    /**
     * EUD-252: invalidates an issued, not yet redeemed authorization code so it can no longer be
     * exchanged at the token endpoint. Idempotent — an unknown or already redeemed code is a no-op.
     */
    void revokeAuthorizationCode(String code);
}
