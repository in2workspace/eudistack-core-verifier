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
class RateLimitFilterTest {

    private RateLimitFilter rateLimitFilter;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain chain;

    @BeforeEach
    void setUp() {
        rateLimitFilter = new RateLimitFilter();
    }

    @Test
    void doFilter_underLimit_shouldPassThrough() throws IOException, ServletException {
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        when(request.getRequestURI()).thenReturn("/oid4vp/auth-request/abc");

        rateLimitFilter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verify(response, never()).setStatus(429);
    }

    @Test
    void doFilter_authEndpointExceedsLimit_shouldReturn429() throws IOException, ServletException {
        when(request.getRemoteAddr()).thenReturn("10.0.0.2");
        when(request.getRequestURI()).thenReturn("/oidc/token");

        // Exceed the 30 req/min auth limit
        for (int i = 0; i < 30; i++) {
            rateLimitFilter.doFilter(request, response, chain);
        }
        reset(response);

        rateLimitFilter.doFilter(request, response, chain);

        verify(response).setStatus(429);
        verify(response).setHeader("Retry-After", "60");
    }

    @Test
    void doFilter_generalEndpointExceedsLimit_shouldReturn429() throws IOException, ServletException {
        when(request.getRemoteAddr()).thenReturn("10.0.0.3");
        when(request.getRequestURI()).thenReturn("/oidc/did/some-id");

        // Exceed the 120 req/min general limit
        for (int i = 0; i < 120; i++) {
            rateLimitFilter.doFilter(request, response, chain);
        }
        reset(response);

        rateLimitFilter.doFilter(request, response, chain);

        verify(response).setStatus(429);
    }

    @Test
    void doFilter_differentIps_shouldNotInterfere() throws IOException, ServletException {
        HttpServletRequest request2 = mock(HttpServletRequest.class);

        when(request.getRemoteAddr()).thenReturn("10.0.0.4");
        when(request.getRequestURI()).thenReturn("/oidc/token");
        when(request2.getRemoteAddr()).thenReturn("10.0.0.5");
        when(request2.getRequestURI()).thenReturn("/oidc/token");

        // Hit limit for first IP
        for (int i = 0; i < 31; i++) {
            rateLimitFilter.doFilter(request, response, chain);
        }

        // Second IP should still pass
        HttpServletResponse response2 = mock(HttpServletResponse.class);
        rateLimitFilter.doFilter(request2, response2, chain);

        verify(response2, never()).setStatus(429);
    }

    @Test
    void doFilter_xForwardedFor_usesFirstIp() throws IOException, ServletException {
        when(request.getHeader("X-Forwarded-For")).thenReturn("192.168.1.1, 10.0.0.1");
        when(request.getRequestURI()).thenReturn("/health");

        rateLimitFilter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }
}
