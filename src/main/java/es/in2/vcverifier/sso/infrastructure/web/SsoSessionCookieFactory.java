package es.in2.vcverifier.sso.infrastructure.web;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import java.time.Duration;

@Component
public class SsoSessionCookieFactory {

    /**
     * Builds the SSO session cookie.
     */
    public ResponseCookie createCookie(
            String tenantSlug,
            String tenantRootDomain,
            Duration ttl,
            String sessionId
    ) {

        String cookieName = "__Secure-sso-" + tenantSlug;

        return ResponseCookie.from(cookieName, sessionId)
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .domain(tenantRootDomain)
                .path("/")
                .maxAge(ttl)
                .build();
    }


}
