package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Set;

public interface AuthorizationResponseProcessorService {

    /**
     * @return the resolved credential claims (JsonNode) extracted from the verified VP, so callers
     * (SSO establishment) can snapshot them for later reuse without re-deriving/re-validating.
     */
    JsonNode handleAuthResponse(String state, String vpToken);

    /**
     * Issues an authorization code directly for an already-authenticated SSO-reused session — no VP
     * is re-presented. Mirrors the code-issuance tail of {@link #handleAuthResponse}, using a
     * credential snapshot captured at the original establishment instead of a freshly-verified VP.
     *
     * @return the redirect URL ({@code redirectUri?code=...&state=...}) to send back to the RP
     */
    String issueCodeForReusedSession(
            RegisteredClient registeredClient,
            String redirectUri,
            Set<String> scopes,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String nonce,
            JsonNode credentialJson
    );
}
