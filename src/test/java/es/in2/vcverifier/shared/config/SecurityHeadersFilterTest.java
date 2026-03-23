package es.in2.vcverifier.shared.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityHeadersFilterTest {

    private SecurityHeadersFilter securityHeadersFilter;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain chain;

    @BeforeEach
    void setUp() {
        securityHeadersFilter = new SecurityHeadersFilter();
    }

    @Test
    void doFilter_shouldSetAllSecurityHeaders() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/oid4vp/auth-response");

        securityHeadersFilter.doFilter(request, response, chain);

        verify(response).setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        verify(response).setHeader("X-Content-Type-Options", "nosniff");
        verify(response).setHeader("X-Frame-Options", "DENY");
        verify(response).setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        verify(response).setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        verify(response).setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        verify(response).setHeader("Cache-Control", "no-store");
        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_jwksEndpoint_shouldNotSetCacheControlNoStore() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/oidc/jwks");

        securityHeadersFilter.doFilter(request, response, chain);

        verify(response).setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        verify(response).setHeader("X-Content-Type-Options", "nosniff");
        verify(response, never()).setHeader(eq("Cache-Control"), anyString());
        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_wellKnownEndpoint_shouldNotSetCacheControlNoStore() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/.well-known/openid-configuration");

        securityHeadersFilter.doFilter(request, response, chain);

        verify(response, never()).setHeader(eq("Cache-Control"), anyString());
        verify(chain).doFilter(request, response);
    }
}
