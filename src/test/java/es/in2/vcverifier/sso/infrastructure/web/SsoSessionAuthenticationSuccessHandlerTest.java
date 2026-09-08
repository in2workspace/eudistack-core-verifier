package es.in2.vcverifier.sso.infrastructure.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.Authentication;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * EUD-149: {@code onAuthenticationSuccess} serializa {@code credentialJson} (JsonNode) a String
 * antes de meterlo en {@link SsoSessionCommand} — cubre ambas ramas de esa conversión: ausente
 * (flujos que no ejercitan SSO) y presente (claims verificadas a snapshotear).
 */
class SsoSessionAuthenticationSuccessHandlerTest {

    private EstablishSsoSessionWorkflow establishSsoSessionWorkflow;
    private SsoSessionCookieFactory cookieFactory;
    private SsoAuditPort auditPort;
    private TenantSsoConfigPort tenantSsoConfigPort;
    private SsoSessionAuthenticationSuccessHandler handler;

    @BeforeEach
    void setUp() {
        establishSsoSessionWorkflow = mock(EstablishSsoSessionWorkflow.class);
        cookieFactory = mock(SsoSessionCookieFactory.class);
        auditPort = mock(SsoAuditPort.class);
        tenantSsoConfigPort = mock(TenantSsoConfigPort.class);
        when(tenantSsoConfigPort.getByTenant(anyString())).thenReturn(Optional.empty());

        handler = new SsoSessionAuthenticationSuccessHandler(
                establishSsoSessionWorkflow, cookieFactory, auditPort, tenantSsoConfigPort);
    }

    @Test
    void onAuthenticationSuccess_noCredentialJson_commandCarriesNullCredentialJson() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(Map.of(
                "tenant", "tenant-a",
                "holderHash", "holder-hash",
                "clientId", "client-a"
        ));

        handler.onAuthenticationSuccess(request, response, authentication);

        ArgumentCaptor<SsoSessionCommand> captor = ArgumentCaptor.forClass(SsoSessionCommand.class);
        verify(establishSsoSessionWorkflow).execute(captor.capture());
        assertNull(captor.getValue().credentialJson());
    }

    @Test
    void onAuthenticationSuccess_withCredentialJson_commandCarriesItsJsonStringRepresentation() throws Exception {
        JsonNode credentialJson = new ObjectMapper().createObjectNode().put("sub", "holder-1");

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(Map.of(
                "tenant", "tenant-a",
                "holderHash", "holder-hash",
                "clientId", "client-a",
                "credentialJson", credentialJson
        ));

        handler.onAuthenticationSuccess(request, response, authentication);

        ArgumentCaptor<SsoSessionCommand> captor = ArgumentCaptor.forClass(SsoSessionCommand.class);
        verify(establishSsoSessionWorkflow).execute(captor.capture());
        assertTrue(captor.getValue().credentialJson().contains("\"sub\":\"holder-1\""));
    }
}
