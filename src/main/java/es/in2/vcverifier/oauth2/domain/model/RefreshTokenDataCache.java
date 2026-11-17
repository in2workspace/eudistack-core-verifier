package es.in2.vcverifier.oauth2.domain.model;

import es.in2.vcverifier.shared.domain.model.AuthenticationResult;
import lombok.Builder;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

@Builder
public record RefreshTokenDataCache(
       OAuth2RefreshToken refreshToken,
       String clientId,
       AuthenticationResult authentication
) {
}
