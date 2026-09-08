package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCredentialCipherPort;
import es.in2.vcverifier.sso.domain.port.SsoMetricsPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regresión (auditoría en vacío 2026-09-07 / EUD-149 production-readiness): el evento
 * {@code SSO_SESSION_ESTABLISHED} publicaba {@code command.sub()} (el sub en claro) en el
 * campo {@code holderHash}, en vez del hash ya calculado. {@code SsoAuditAdapter.prefix()}
 * trunca ese campo SIN volver a hashearlo para el log {@code holderHashPrefix} — a diferencia
 * de {@code maskSubject()}, que sí re-hashea para el campo {@code sub} — así que ese caller
 * filtraba los primeros 8 caracteres del sub en claro en cada login SSO exitoso, violando
 * NFR-S-149-01/AC-10 ("el sub del Holder nunca se persiste ni se registra en claro").
 */
class EstablishSsoSessionWorkflow_AuditHolderHashTest {

    private static final String TENANT = "tenant-a";
    private static final String RAW_SUB = "did:key:z6MkVerySensitiveSubjectValue";
    private static final String HASHED_SUB = "9f86d081884c7d65"; // valor fijo devuelto por el mock

    @Test
    @DisplayName("SSO_SESSION_ESTABLISHED audita el holderHash ya hasheado, nunca el sub en claro")
    void execute_publishesHashedHolderHash_neverRawSub() {

        TenantSsoConfigPort configPort = mock(TenantSsoConfigPort.class);
        SsoSessionRepositoryPort sessionRepositoryPort = mock(SsoSessionRepositoryPort.class);
        SsoAuditPort auditPort = mock(SsoAuditPort.class);
        SsoMetricsPort metricsPort = mock(SsoMetricsPort.class);
        HashingService hashingService = mock(HashingService.class);
        SsoCredentialCipherPort credentialCipherPort = mock(SsoCredentialCipherPort.class);

        TenantSsoConfig config = new TenantSsoConfig(
                TENANT, "example.com", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(8), Duration.ofMinutes(30)),
                List.of());

        when(configPort.getByTenant(TENANT)).thenReturn(Optional.of(config));
        when(configPort.resolveTtl(TENANT)).thenReturn(SsoSessionTtl.systemDefault());
        when(hashingService.sha256(RAW_SUB)).thenReturn(HASHED_SUB);

        EstablishSsoSessionWorkflow workflow = new EstablishSsoSessionWorkflow(
                configPort, sessionRepositoryPort, auditPort, metricsPort,
                hashingService, Clock.systemUTC(), credentialCipherPort);

        SsoSessionCommand command = new SsoSessionCommand(TENANT, RAW_SUB, "client-a", "corr-1",
                "{\"sub\":\"" + RAW_SUB + "\"}");

        workflow.execute(command);

        org.mockito.ArgumentCaptor<SsoAuditEvent> captor =
                org.mockito.ArgumentCaptor.forClass(SsoAuditEvent.class);
        verify(auditPort).publish(captor.capture());

        assertEquals(SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED, captor.getValue().getEventType());
        assertEquals(HASHED_SUB, captor.getValue().getHolderHash());
        assertNotEquals(RAW_SUB, captor.getValue().getHolderHash());
    }
}
