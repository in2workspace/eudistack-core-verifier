package es.in2.vcverifier.oauth2.infrastructure.config;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

public class IdTokenUserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

    private static final Set<String> PROTOCOL_CLAIMS = Set.of(
            JwtClaimNames.ISS, JwtClaimNames.AUD, JwtClaimNames.EXP, JwtClaimNames.IAT, JwtClaimNames.NBF,
            JwtClaimNames.JTI, IdTokenClaimNames.NONCE, IdTokenClaimNames.AZP, IdTokenClaimNames.AT_HASH,
            IdTokenClaimNames.C_HASH, IdTokenClaimNames.AUTH_TIME, "sid");

    @Override
    public OidcUserInfo apply(OidcUserInfoAuthenticationContext context) {
        OAuth2Authorization.Token<OidcIdToken> idToken = context.getAuthorization().getToken(OidcIdToken.class);
        if (idToken == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        Map<String, Object> claims = new LinkedHashMap<>(idToken.getToken().getClaims());
        PROTOCOL_CLAIMS.forEach(claims::remove);
        return new OidcUserInfo(claims);
    }
}
