package es.in2.vcverifier.sso.infrastructure.web;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.sso.application.service.HashingService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * EUD-252: browser-binding cookie of an in-flight SSO login ({@code __Host-sso-tx}).
 *
 * <p>Set on the /authorize redirect to the login page and checked by the cross-device close
 * endpoint, so only the browser that started a login can turn the wallet's presentation into an
 * SSO session — the public {@code state} of the SSE channel is not enough to hijack it.
 *
 * <p>{@code __Host-} prefix: Secure, Path=/ and no Domain, so it is bound to the exact Verifier
 * host the browser used at /authorize and can't be planted from a sibling subdomain.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SsoBrowserBindingCookie {

    public static final String COOKIE_NAME = "__Host-sso-tx";

    /**
     * Request attribute through which the authorization request converter (which has no response
     * object) hands the cookie value to {@code CustomErrorResponseHandler}, which emits it.
     */
    public static final String PENDING_VALUE_ATTRIBUTE = SsoBrowserBindingCookie.class.getName() + ".PENDING_VALUE";

    static final Duration MAX_AGE = Duration.ofSeconds(600);

    // 256-bit value, base64url without padding → exactly 43 characters of the URL-safe alphabet.
    private static final Pattern VALUE_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    private final TenantSsoConfigPort tenantSsoConfigPort;
    private final HashingService hashingService;
    private final SsoSessionCookieFactory sessionCookieFactory;

    /**
     * Binds the login being started to this browser when the request's tenant has SSO enabled.
     * Reuses an existing well-formed cookie value (several tabs of the same browser logging in
     * concurrently must not invalidate each other), otherwise generates a fresh one. The value is
     * left in {@link #PENDING_VALUE_ATTRIBUTE} for the response handler to (re-)emit.
     *
     * @return SHA-256 (hex) of the binding value, or {@code null} if the tenant has no SSO (EC-07:
     * SSO-disabled tenants keep the legacy flow untouched)
     */
    public String bindIfSsoEnabled(HttpServletRequest request) {
        String tenant = TenantDomainFilter.getCurrentTenant(request);
        if (tenant == null || tenant.isBlank() || !isSsoEnabled(tenant)) {
            return null;
        }
        String value = readValue(request).orElseGet(sessionCookieFactory::generateOpaqueSessionId);
        request.setAttribute(PENDING_VALUE_ATTRIBUTE, value);
        return hashingService.sha256(value);
    }

    /** The well-formed browser-binding value carried by the request, if any. */
    public Optional<String> readValue(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (COOKIE_NAME.equals(cookie.getName())
                    && cookie.getValue() != null
                    && VALUE_PATTERN.matcher(cookie.getValue()).matches()) {
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    /** The cookie to emit for this request, if {@link #bindIfSsoEnabled} bound it. */
    public static Optional<ResponseCookie> pendingCookie(HttpServletRequest request) {
        Object value = request.getAttribute(PENDING_VALUE_ATTRIBUTE);
        return value instanceof String s && !s.isBlank() ? Optional.of(build(s)) : Optional.empty();
    }

    static ResponseCookie build(String value) {
        return ResponseCookie.from(COOKIE_NAME, value)
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path("/")
                .maxAge(MAX_AGE)
                .build();
    }

    private boolean isSsoEnabled(String tenant) {
        try {
            return tenantSsoConfigPort.getByTenant(tenant).filter(TenantSsoConfig::ssoEnabled).isPresent();
        } catch (RuntimeException e) {
            // Unreadable config → no binding → no SSO for this login; the OID4VP login itself proceeds.
            log.warn("event=sso_browser_binding_skipped tenant={} reason=config_unavailable", tenant);
            return false;
        }
    }
}
