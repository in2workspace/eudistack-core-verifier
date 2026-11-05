package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.shared.domain.model.AuthenticationResult;
import es.in2.vcverifier.shared.domain.model.CertificateAuthentication;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

public interface AuthorizationResponseProcessorService {

    /**
     * Verifies the wallet's VP and issues the authorization code. Validation failures are still
     * notified to the browser over SSE ({@code validation_failed}) by this method; the success
     * redirect is NOT sent here (EUD-252) — the caller decides where the browser must go.
     *
     * @param tenant tenant resolved on the wallet's request; must match the tenant the login was
     *               started on at /authorize (EUD-252), otherwise the response is rejected
     * @return the verified credential claims plus everything the caller needs to route the
     * browser: the RP redirect URL, the issued code and the browser-binding hash of the login
     */
    AuthResponseResult handleAuthResponse(String state, String vpToken, String tenant);

    /**
     * Issues an authorization code directly for an already-authenticated SSO-reused session — no VP
     * or certificate is presented again. Mirrors the code-issuance tail of {@link #handleAuthResponse},
     * using the authentication snapshot captured at the original establishment.
     * The caller MUST have already validated {@code redirectUri} against the client's registered
     * redirect URIs — this method does not repeat that check.
     *
     * @param authentication authentication of the session, whose {@code auth_time} is the original
     *                       login, not this reuse
     * @param issuer   issuer of the {@code /oidc/authorize} request, sent as {@code iss} (RFC 9207)
     *
     * @return the redirect URL ({@code redirectUri?code=...&state=...&iss=...}) to send back to the RP
     */
    String issueCodeForReusedSession(
            String clientId,
            String redirectUri,
            Set<String> scopes,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String nonce,
            AuthenticationResult authentication,
            String issuer
    );

    /**
     * Consumes the open login of {@code state} and issues its authorization code for a login with a
     * certificate. Empty when the login is gone, expired, of another tenant or of an unknown client.
     */
    Optional<AuthResponseResult> issueCodeForCertificateLogin(String state, String tenant,
                                                              CertificateAuthentication authentication);

    /**
     * EUD-252: invalidates an issued, not yet redeemed authorization code so it can no longer be
     * exchanged at the token endpoint. Idempotent — an unknown or already redeemed code is a no-op.
     */
    void revokeAuthorizationCode(String code);
}
