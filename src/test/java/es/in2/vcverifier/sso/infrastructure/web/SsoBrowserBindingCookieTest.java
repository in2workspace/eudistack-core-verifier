package es.in2.vcverifier.sso.infrastructure.web;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SsoBrowserBindingCookieTest {

    private static final String TENANT = "tenant-a";
    private static final String EXISTING_VALUE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO_-";

    @Mock private TenantSsoConfigPort tenantSsoConfigPort;

    private final HashingService hashingService = new HashingService();
    private SsoBrowserBindingCookie bindingCookie;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        bindingCookie = new SsoBrowserBindingCookie(tenantSsoConfigPort, hashingService, new SsoSessionCookieFactory());
        request = new MockHttpServletRequest();
        request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, TENANT);
    }

    @Test
    void bindIfSsoEnabled_ssoTenantWithoutCookie_generatesFreshValueAndReturnsItsHash() {
        // Given
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config(true)));

        // When
        String hash = bindingCookie.bindIfSsoEnabled(request);

        // Then: 256-bit base64url value pending for the response, hash = SHA-256(value)
        Object pending = request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE);
        assertThat(pending).isInstanceOf(String.class);
        assertThat((String) pending).matches("^[A-Za-z0-9_-]{43}$");
        assertThat(hash).isEqualTo(hashingService.sha256((String) pending));
    }

    @Test
    void bindIfSsoEnabled_ssoTenantWithExistingCookie_reusesItsValue() {
        // Given: another tab of the same browser already holds a binding
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config(true)));
        request.setCookies(new Cookie(SsoBrowserBindingCookie.COOKIE_NAME, EXISTING_VALUE));

        // When
        String hash = bindingCookie.bindIfSsoEnabled(request);

        // Then
        assertThat(request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE)).isEqualTo(EXISTING_VALUE);
        assertThat(hash).isEqualTo(hashingService.sha256(EXISTING_VALUE));
    }

    @Test
    void bindIfSsoEnabled_malformedExistingCookie_isReplaced() {
        // Given
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config(true)));
        request.setCookies(new Cookie(SsoBrowserBindingCookie.COOKIE_NAME, "short"));

        // When
        bindingCookie.bindIfSsoEnabled(request);

        // Then
        assertThat((String) request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE))
                .isNotEqualTo("short")
                .matches("^[A-Za-z0-9_-]{43}$");
    }

    @Test
    void bindIfSsoEnabled_ssoDisabledTenant_doesNotBind() {
        // Given
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config(false)));

        // When
        String hash = bindingCookie.bindIfSsoEnabled(request);

        // Then
        assertThat(hash).isNull();
        assertThat(request.getAttribute(SsoBrowserBindingCookie.PENDING_VALUE_ATTRIBUTE)).isNull();
        assertThat(SsoBrowserBindingCookie.pendingCookie(request)).isEmpty();
    }

    @Test
    void bindIfSsoEnabled_noTenant_doesNotBind() {
        // Given
        request.removeAttribute(TenantDomainFilter.TENANT_ATTRIBUTE);

        // When / Then
        assertThat(bindingCookie.bindIfSsoEnabled(request)).isNull();
    }

    @Test
    void pendingCookie_afterBinding_hasHostPrefixAttributes() {
        // Given
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config(true)));
        bindingCookie.bindIfSsoEnabled(request);

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

    private static TenantSsoConfig config(boolean ssoEnabled) {
        return new TenantSsoConfig(TENANT, "example.com", ssoEnabled,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)), List.of());
    }
}
