package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;

import java.util.Map;

import static es.in2.vcverifier.shared.config.TenantDomainFilter.TENANT_ATTRIBUTE;
import static es.in2.vcverifier.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TenantDomainFilterTest {

    private static final int CERTIFICATE_PORT = 8081;

    private TenantDomainFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;

    @BeforeEach
    void setUp() {
        filter = new TenantDomainFilter(new CertificateLoginProperties(CERTIFICATE_PORT, Map.of(
                "cgcom", new CertificateLoginProperties.Tenant(
                        "login-cgcom.certificados.example.com", "https://cgcom.example.com"))));
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
    }

    @Nested
    class CertificatePort {

        @BeforeEach
        void onTheCertificatePort() {
            when(request.getLocalPort()).thenReturn(CERTIFICATE_PORT);
        }

        @Test
        void doFilterInternal_certificateSubdomain_dropsTheCertSuffix() throws Exception {
            when(request.getServerName()).thenReturn("kpmg-cert.eudistack.net");

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "kpmg");
            verify(chain).doFilter(request, response);
        }

        @Test
        void doFilterInternal_configuredCertificateHost_usesItsTenant() throws Exception {
            when(request.getServerName()).thenReturn("LOGIN-CGCOM.certificados.example.com");

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "cgcom");
        }

        @Test
        void doFilterInternal_tenantHeader_isIgnored() throws Exception {
            when(request.getServerName()).thenReturn("kpmg-cert.eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn("cgcom");

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "kpmg");
            verify(request, never()).setAttribute(TENANT_ATTRIBUTE, "cgcom");
        }

        @Test
        void doFilterInternal_tenantHeaderWithoutUsableHost_setsNoTenant() throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn("cgcom");

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
            verify(chain).doFilter(request, response);
        }

        @Test
        void doFilterInternal_onlyTheCertSuffix_setsNoTenant() throws Exception {
            when(request.getServerName()).thenReturn("-cert.eudistack.net");

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }

        @Test
        void doFilterInternal_hostWithoutTheCertSuffix_usesTheFirstSegment() throws Exception {
            when(request.getServerName()).thenReturn("dome.127.0.0.1.nip.io");

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "dome");
        }
    }

    // ──────────────────────────────────────────────────────────
    // Hostname subdomain extraction (primary path)
    // ──────────────────────────────────────────────────────────

    @Nested
    class HostnameSubdomain {

        @Test
        void doFilterInternal_standardSubdomain_setsTenantAttribute() throws Exception {
            when(request.getServerName()).thenReturn("kpmg.eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "kpmg");
            verify(chain).doFilter(request, response);
        }

        @Test
        void doFilterInternal_nipIoSubdomain_setsTenantAttribute() throws Exception {
            when(request.getServerName()).thenReturn("dome.127.0.0.1.nip.io");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "dome");
        }

        @Test
        void doFilterInternal_subdomain_lowercaseNormalized() throws Exception {
            when(request.getServerName()).thenReturn("KPMG.eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "kpmg");
        }

        @Test
        void doFilterInternal_subdomainWithHyphenAndDigits_setsTenantAttribute() throws Exception {
            when(request.getServerName()).thenReturn("my-tenant-123.eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "my-tenant-123");
        }

        @Test
        void doFilterInternal_hostnameWithNoDot_doesNotSetAttribute() throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }

        @Test
        void doFilterInternal_hostnameStartsWithDot_doesNotSetAttribute() throws Exception {
            when(request.getServerName()).thenReturn(".eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }

        @Test
        void doFilterInternal_invalidSubdomainWithSpaces_doesNotSetAttribute() throws Exception {
            when(request.getServerName()).thenReturn("invalid tenant.eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }

        @Test
        void doFilterInternal_nullHostname_doesNotSetAttribute() throws Exception {
            when(request.getServerName()).thenReturn(null);
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }

        @Test
        void doFilterInternal_blankHostname_doesNotSetAttribute() throws Exception {
            when(request.getServerName()).thenReturn("   ");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }
    }

    // ──────────────────────────────────────────────────────────
    // X-Tenant header fallback (new path)
    // ──────────────────────────────────────────────────────────

    @Nested
    class XTenantHeaderFallback {

        @Test
        void doFilterInternal_noSubdomainValidHeader_setsTenantFromHeader() throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn("dome");

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "dome");
        }

        @Test
        void doFilterInternal_header_lowercaseNormalized() throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn("DOME");

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "dome");
        }

        @Test
        void doFilterInternal_headerWithHyphenAndDigits_setsTenantAttribute() throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn("my-tenant-99");

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "my-tenant-99");
        }

        @Test
        void doFilterInternal_nullHeader_doesNotSetAttribute() throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }

        @Test
        void doFilterInternal_blankHeader_doesNotSetAttribute() throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn("   ");

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }

        @ParameterizedTest
        @ValueSource(strings = {"invalid tenant", "tenant!", "ten@ant", "ten/ant"})
        void doFilterInternal_invalidHeaderFormat_doesNotSetAttribute(String headerValue) throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(headerValue);

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }
    }

    // ──────────────────────────────────────────────────────────
    // Priority: X-Tenant header takes precedence over subdomain
    // ──────────────────────────────────────────────────────────

    @Nested
    class Priority {

        @Test
        void doFilterInternal_bothSubdomainAndHeader_headerWins() throws Exception {
            when(request.getServerName()).thenReturn("kpmg.eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn("other");

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "other");
            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), eq("kpmg"));
            verify(chain).doFilter(request, response);
        }

        @Test
        void doFilterInternal_invalidSubdomainValidHeader_usesHeader() throws Exception {
            when(request.getServerName()).thenReturn("invalid tenant.eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn("dome");

            filter.doFilterInternal(request, response, chain);

            verify(request).setAttribute(TENANT_ATTRIBUTE, "dome");
        }

        @Test
        void doFilterInternal_noSubdomainNoHeader_doesNotSetAttribute() throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            filter.doFilterInternal(request, response, chain);

            verify(request, never()).setAttribute(eq(TENANT_ATTRIBUTE), any());
        }
    }

    // ──────────────────────────────────────────────────────────
    // MDC lifecycle
    // ──────────────────────────────────────────────────────────

    @Nested
    class MdcLifecycle {

        @Test
        void doFilterInternal_tenantResolved_mdcSetDuringChainAndClearedAfter() throws Exception {
            when(request.getServerName()).thenReturn("dome.eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            doAnswer(invocation -> {
                assertEquals("dome", MDC.get("tenantDomain"));
                return null;
            }).when(chain).doFilter(request, response);

            filter.doFilterInternal(request, response, chain);

            assertNull(MDC.get("tenantDomain"));
        }

        @Test
        void doFilterInternal_mdcClearedEvenIfChainThrows() throws Exception {
            when(request.getServerName()).thenReturn("dome.eudistack.net");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);
            doThrow(new RuntimeException("chain failure")).when(chain).doFilter(request, response);

            assertThrows(RuntimeException.class,
                    () -> filter.doFilterInternal(request, response, chain));

            assertNull(MDC.get("tenantDomain"));
        }

        @Test
        void doFilterInternal_noTenantResolved_mdcNotSet() throws Exception {
            when(request.getServerName()).thenReturn("localhost");
            when(request.getHeader(X_TENANT_HEADER)).thenReturn(null);

            doAnswer(invocation -> {
                assertNull(MDC.get("tenantDomain"));
                return null;
            }).when(chain).doFilter(request, response);

            filter.doFilterInternal(request, response, chain);
        }
    }

    // ──────────────────────────────────────────────────────────
    // getCurrentTenant helper
    // ──────────────────────────────────────────────────────────

    @Nested
    class GetCurrentTenant {

        @Test
        void getCurrentTenant_attributePresent_returnsTenant() {
            when(request.getAttribute(TENANT_ATTRIBUTE)).thenReturn("dome");

            assertEquals("dome", TenantDomainFilter.getCurrentTenant(request));
        }

        @Test
        void getCurrentTenant_attributeAbsent_returnsNull() {
            when(request.getAttribute(TENANT_ATTRIBUTE)).thenReturn(null);

            assertNull(TenantDomainFilter.getCurrentTenant(request));
        }

        @Test
        void getCurrentTenant_attributeNotString_returnsNull() {
            when(request.getAttribute(TENANT_ATTRIBUTE)).thenReturn(42);

            assertNull(TenantDomainFilter.getCurrentTenant(request));
        }
    }
}
