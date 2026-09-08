package es.in2.vcverifier.sso.infrastructure.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * EUD-149: {@code onAuthenticationSuccess} serializa {@code credentialJson} (JsonNode) a String
 * antes de meterlo en {@link SsoSessionCommand} — cubre ambas ramas de esa conversión: ausente
 * (flujos que no ejercitan SSO) y presente (claims verificadas a snapshotear).
 * <p>
 * B2 (review): cubre también que el handler nunca publica el {@code sub} en claro en un evento
 * de auditoría, y que ya no duplica {@code SSO_SESSION_ESTABLISHED} (lo publica únicamente
 * {@link EstablishSsoSessionWorkflow}, con el hash correcto, en la misma transacción que la fila).
 */
class SsoSessionAuthenticationSuccessHandlerTest {

    private EstablishSsoSessionWorkflow establishSsoSessionWorkflow;
    private SsoSessionCookieFactory cookieFactory;
    private SsoAuditPort auditPort;
    private TenantSsoConfigPort tenantSsoConfigPort;
    private HashingService hashingService;
    private SsoSessionAuthenticationSuccessHandler handler;

    @BeforeEach
    void setUp() {
        establishSsoSessionWorkflow = mock(EstablishSsoSessionWorkflow.class);
        cookieFactory = mock(SsoSessionCookieFactory.class);
        auditPort = mock(SsoAuditPort.class);
        tenantSsoConfigPort = mock(TenantSsoConfigPort.class);
        hashingService = mock(HashingService.class);
        when(tenantSsoConfigPort.getByTenant(anyString())).thenReturn(Optional.empty());

        handler = new SsoSessionAuthenticationSuccessHandler(
                establishSsoSessionWorkflow, cookieFactory, auditPort, tenantSsoConfigPort, hashingService);
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

    @Test
    void onAuthenticationSuccess_establishmentSucceeds_doesNotPublishDuplicateSessionEstablishedEvent() throws Exception {
        // B2 (review): EstablishSsoSessionWorkflow already publishes SSO_SESSION_ESTABLISHED
        // (correctly hashed) in the same transaction as the persisted row — this handler must
        // not publish a second one.
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(Map.of(
                "tenant", "tenant-a",
                "holderHash", "did:key:zRawSubjectValue",
                "clientId", "client-a"
        ));

        EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor descriptor =
                new EstablishSsoSessionWorkflow.SsoSessionCookieDescriptor(
                        "SSO_SESSION", "session-value", Instant.now().plusSeconds(3600));
        when(establishSsoSessionWorkflow.execute(any())).thenReturn(descriptor);
        when(cookieFactory.createCookie(anyString(), anyString(), any(Duration.class), anyString()))
                .thenReturn(ResponseCookie.from("__Secure-sso-tenant-a", "session-value").build());

        handler.onAuthenticationSuccess(request, response, authentication);

        verifyNoInteractions(auditPort);
        verify(response).addHeader(org.mockito.ArgumentMatchers.eq("Set-Cookie"), anyString());
    }

    @Test
    void onAuthenticationSuccess_establishmentFails_publishesHashedHolderHash_neverRawSub() throws Exception {
        String rawSub = "did:key:zRawSubjectValue";
        String hashed = "sha256-hashed-value";

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(Map.of(
                "tenant", "tenant-a",
                "holderHash", rawSub,
                "clientId", "client-a"
        ));

        when(hashingService.sha256(rawSub)).thenReturn(hashed);
        when(establishSsoSessionWorkflow.execute(any())).thenReturn(null);

        handler.onAuthenticationSuccess(request, response, authentication);

        ArgumentCaptor<SsoAuditEvent> eventCaptor = ArgumentCaptor.forClass(SsoAuditEvent.class);
        verify(auditPort).publish(eventCaptor.capture());

        assertEquals(SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED, eventCaptor.getValue().getEventType());
        assertEquals(hashed, eventCaptor.getValue().getHolderHash());
        assertTrue(!eventCaptor.getValue().getHolderHash().equals(rawSub),
                "holderHashPrefix must never be derivable from the raw sub");
    }
}
