package es.in2.vcverifier.oauth2.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.time.Instant;
import java.util.Set;

@Builder
public record AuthorizationCodeData(
        String state,
        JsonNode verifiableCredential,
        Set<String> requestedScopes,
        OAuth2Authorization oAuth2Authorization,
        String clientNonce,
        // EUD-300 (OIDC Core §2 auth_time): original authentication time of a code issued by SSO
        // reuse; null when the code comes from a fresh VP presentation (auth_time = now).
        Instant authTime
) {
}
