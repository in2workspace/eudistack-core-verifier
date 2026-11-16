package es.in2.vcverifier.oauth2.domain.model;

import es.in2.vcverifier.shared.domain.model.AuthenticationResult;
import lombok.Builder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.util.Set;

@Builder
public record AuthorizationCodeData(
        String state,
        AuthenticationResult authentication,
        Set<String> requestedScopes,
        OAuth2Authorization oAuth2Authorization,
        String clientNonce
) {
}
