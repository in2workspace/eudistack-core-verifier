package es.in2.vcverifier.sso.infrastructure.web;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

@Component
public class SsoSessionCookieFactory {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generates a cryptographically secure opaque session identifier.
     * AD-2:
     * - 256 bits entropy
     * - URL-safe Base64
     * - no padding
     */
    public String generateOpaqueSessionId() {

        byte[] randomBytes = new byte[32]; // 256 bits

        SECURE_RANDOM.nextBytes(randomBytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
    }

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
