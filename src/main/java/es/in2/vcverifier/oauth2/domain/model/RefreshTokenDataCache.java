package es.in2.vcverifier.oauth2.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

@Builder
public record RefreshTokenDataCache(
       OAuth2RefreshToken refreshToken,
       String clientId,
       JsonNode verifiableCredential,
       // Epoch-seconds of the ORIGINAL authentication's auth_time claim — must be carried forward
       // unchanged across every subsequent refresh (OIDC Core 12.2 / angular-auth-oidc-client's
       // pre/post id_token claims check), never recomputed as "now" on refresh.
       Long authTimeEpochSeconds

) {
}
