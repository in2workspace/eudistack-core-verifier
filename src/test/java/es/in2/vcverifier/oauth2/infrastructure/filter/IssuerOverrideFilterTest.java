package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.shared.config.BackendConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuerOverrideFilterTest {

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private AuthorizationServerSettings settings;
    private IssuerOverrideFilter filter;

    @BeforeEach
    void setUp() {
        settings = AuthorizationServerSettings.builder().build();
        filter = new IssuerOverrideFilter(backendConfig, settings);
    }

    @AfterEach
    void tearDown() {
        AuthorizationServerContextHolder.resetContext();
    }

    @Test
    void doFilterInternal_canonicalRequest_setsIssuerWithContextPath() throws Exception {
        when(backendConfig.getUrl()).thenReturn("https://verifier-dome.host:4443/verifier");
        AtomicReference<String> capturedIssuer = new AtomicReference<>();

        FilterChain chain = (req, res) ->
                capturedIssuer.set(AuthorizationServerContextHolder.getContext().getIssuer());

        filter.doFilterInternal(request, response, chain);

        assertEquals("https://verifier-dome.host:4443/verifier", capturedIssuer.get());
    }

    @Test
    void doFilterInternal_nonCanonicalRequest_setsIssuerWithoutContextPath() throws Exception {
        when(backendConfig.getUrl()).thenReturn("https://verifier-dome.host:4443");
        AtomicReference<String> capturedIssuer = new AtomicReference<>();

        FilterChain chain = (req, res) ->
                capturedIssuer.set(AuthorizationServerContextHolder.getContext().getIssuer());

        filter.doFilterInternal(request, response, chain);

        assertEquals("https://verifier-dome.host:4443", capturedIssuer.get());
    }

    @Test
    void doFilterInternal_contextExposesInjectedSettings() throws Exception {
        when(backendConfig.getUrl()).thenReturn("https://host/verifier");
        AtomicReference<AuthorizationServerSettings> capturedSettings = new AtomicReference<>();

        FilterChain chain = (req, res) ->
                capturedSettings.set(AuthorizationServerContextHolder.getContext().getAuthorizationServerSettings());

        filter.doFilterInternal(request, response, chain);

        assertSame(settings, capturedSettings.get());
    }

    @Test
    void doFilterInternal_contextIsResetAfterChainCompletes() throws Exception {
        when(backendConfig.getUrl()).thenReturn("https://host/verifier");

        filter.doFilterInternal(request, response, (req, res) -> { /* no-op */ });

        assertNull(AuthorizationServerContextHolder.getContext());
    }

    @Test
    void doFilterInternal_contextIsResetEvenWhenChainThrows() throws Exception {
        when(backendConfig.getUrl()).thenReturn("https://host/verifier");

        FilterChain throwingChain = (req, res) -> { throw new RuntimeException("chain failure"); };

        assertThrows(RuntimeException.class,
                () -> filter.doFilterInternal(request, response, throwingChain));
        assertNull(AuthorizationServerContextHolder.getContext());
    }
}
