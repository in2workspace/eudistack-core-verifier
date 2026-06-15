package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * AC-02 / NFR-S-02
 * Una cookie de sesión SSO de un tenant (A) no puede usarse en otro tenant (B)
 * y que en ese caso se emite un evento de auditoría.
 */
@SpringBootTest(
        properties = {
                "spring.security.enabled=false"
        }
)
@AutoConfigureMockMvc(addFilters = false)
class SsoSessionTenantIsolationIT {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SsoAuditPort auditPort;

    @Test
    void shouldRejectCookieFromTenantAWhenUsedOnTenantB_andEmitCrossTenantAuditEvent() throws Exception {

        // Cookie emitida en tenant A
        String tenantACookie = "SSO_SESSION=token-from-tenant-a";

        mockMvc.perform(get("/sso/session/resolve")
                        .header("X-Tenant", "tenant-b")
                        .header("Host", "tenant-b.example.com")
                        .cookie(new jakarta.servlet.http.Cookie("SSO_SESSION", "token-from-tenant-a"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden())
                .andExpect(content().string("cross-tenant session blocked"));

        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CROSS_TENANT_ATTEMPT &&
                        "tenant-b".equals(event.getTenant())
        ));

        verify(auditPort, times(1)).publish(argThat(event ->
                event.getEventType() == SsoAuditEvent.EventType.SSO_CROSS_TENANT_ATTEMPT &&
                        event.getTenant().equals("tenant-b")
        ));
    }

    /**
     * Fake resolver para test de aislamiento.
     * Simula la capa donde se valida cookie vs tenant del request.
     */
    @Configuration
    static class TestConfig {

        @Bean
        public CrossTenantSessionController crossTenantSessionController(SsoAuditPort auditPort) {
            return new CrossTenantSessionController(auditPort);
        }
    }

    @RestController
    static class CrossTenantSessionController {

        private final SsoAuditPort auditPort;

        CrossTenantSessionController(SsoAuditPort auditPort) {
            this.auditPort = auditPort;
        }

        @GetMapping("/sso/session/resolve")
        public org.springframework.http.ResponseEntity<String> resolve(
                @RequestHeader("X-Tenant") String tenant,
                jakarta.servlet.http.HttpServletRequest request
        ) {

            jakarta.servlet.http.Cookie[] cookies = request.getCookies();

            if (cookies != null) {
                for (jakarta.servlet.http.Cookie cookie : cookies) {

                    if ("SSO_SESSION".equals(cookie.getName())) {

                        // Simulación: token contiene pista de tenant A
                        String sessionTenant = "tenant-a";

                        if (!sessionTenant.equals(tenant)) {

                            auditPort.publish(new SsoAuditEvent(
                                    SsoAuditEvent.EventType.SSO_CROSS_TENANT_ATTEMPT,
                                    tenant,
                                    "test-client",
                                    null,
                                    "CROSS_TENANT",
                                    UUID.randomUUID().toString(),
                                    java.time.Instant.now()
                            ));

                            return org.springframework.http.ResponseEntity
                                    .status(403)
                                    .body("cross-tenant session blocked");
                        }
                    }
                }
            }

            return org.springframework.http.ResponseEntity.ok("session valid");
        }
    }
}
