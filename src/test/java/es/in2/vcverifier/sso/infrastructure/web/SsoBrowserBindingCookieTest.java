package es.in2.vcverifier.sso.infrastructure.web;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.sso.application.service.HashingService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class SsoBrowserBindingCookieTest {

    private static final String TENANT = "tenant-a";
    private static final String EXISTING_VALUE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO_-";

    private final HashingService hashingService = new HashingService();
    private SsoBrowserBindingCookie bindingCookie;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        bindingCookie = new SsoBrowserBindingCookie(hashingService, new SsoSessionCookieFactory());
        request = new MockHttpServletRequest();
        request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, TENANT);
    }

    @Test
    void bind_withoutCookie_generatesFreshValueAndReturnsItsHash() {
        // When
        String hash = bindingCookie.bind(request);

        // Then: 256-bit base64url value pending for the response, hash = SHA-256(value)
        Object pending = request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE);
        assertThat(pending).isInstanceOf(String.class);
        assertThat((String) pending).matches("^[A-Za-z0-9_-]{43}$");
        assertThat(hash).isEqualTo(hashingService.sha256((String) pending));
    }

    @Test
    void bind_withExistingCookie_reusesItsValue() {
        // Given: another tab of the same browser already holds a binding
        request.setCookies(new Cookie(SsoBrowserBindingCookie.COOKIE_NAME, EXISTING_VALUE));

        // When
        String hash = bindingCookie.bind(request);

        // Then
        assertThat(request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE)).isEqualTo(EXISTING_VALUE);
        assertThat(hash).isEqualTo(hashingService.sha256(EXISTING_VALUE));
    }

    @Test
    void bind_malformedExistingCookie_isReplaced() {
        // Given
        request.setCookies(new Cookie(SsoBrowserBindingCookie.COOKIE_NAME, "short"));

        // When
        bindingCookie.bind(request);

        // Then
        assertThat((String) request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE))
                .isNotEqualTo("short")
                .matches("^[A-Za-z0-9_-]{43}$");
    }

    @Test
    void bind_noTenant_stillBinds() {
        // Given
        request.removeAttribute(TenantDomainFilter.TENANT_ATTRIBUTE);

        // When / Then
        assertThat(bindingCookie.bind(request)).isNotNull();
        assertThat(SsoBrowserBindingCookie.pendingCookie(request)).isPresent();
    }

    @Test
    void pendingCookie_afterBinding_hasHostPrefixAttributes() {
        // Given
        bindingCookie.bind(request);

        // When
        var cookie = SsoBrowserBindingCookie.pendingCookie(request).orElseThrow();

        // Then
        assertThat(cookie.getName()).isEqualTo("__Host-sso-tx");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getSameSite()).isEqualTo("Lax");
        assertThat(cookie.getPath()).isEqualTo("/");
        assertThat(cookie.getDomain()).isNull();
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofSeconds(600));
    }

    @Test
    void pendingCookie_withoutBinding_isEmpty() {
        assertThat(SsoBrowserBindingCookie.pendingCookie(request)).isEmpty();
    }
}
