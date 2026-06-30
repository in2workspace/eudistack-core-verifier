package es.in2.vcverifier.sso.application.catalog;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoCatalogRepositoryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManageTenantSsoCatalogServiceTest {

    @Mock
    SsoCatalogRepositoryPort catalogRepository;

    @Mock
    SsoAuditPort auditPort;

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-01-01T10:00:00Z"), ZoneOffset.UTC);
    private static final String TENANT = "tenant-a";
    private static final String CLIENT_ID = "client-x";

    private ManageTenantSsoCatalogService service;

    @BeforeEach
    void setUp() {
        service = new ManageTenantSsoCatalogService(catalogRepository, auditPort, CLOCK);
    }

    // =========================================================
    // listEligibleClients
    // =========================================================

    @Test
    void listEligibleClients_returnsClientIds_fromRepository() {
        when(catalogRepository.listClients(TENANT)).thenReturn(List.of(
                SsoEligibleClient.of("client-x"),
                SsoEligibleClient.of("client-y")
        ));

        List<String> result = service.listEligibleClients(TENANT);

        assertThat(result).containsExactlyInAnyOrder("client-x", "client-y");
    }

    @Test
    void listEligibleClients_returnsEmptyList_whenNoClientsRegistered() {
        when(catalogRepository.listClients(TENANT)).thenReturn(List.of());

        List<String> result = service.listEligibleClients(TENANT);

        assertThat(result).isEmpty();
    }

    @Test
    void listEligibleClients_throwsNullPointerException_whenTenantIsNull() {
        assertThatThrownBy(() -> service.listEligibleClients(null))
                .isInstanceOf(NullPointerException.class);
    }

    // =========================================================
    // addEligibleClient — EC-04 idempotencia
    // =========================================================

    @Test
    void addEligibleClient_emitsAddedEvent_whenClientWasAbsent() {
        AddEligibleClientCommand command = new AddEligibleClientCommand(TENANT, CLIENT_ID);
        when(catalogRepository.addIfAbsent(TENANT, SsoEligibleClient.of(CLIENT_ID))).thenReturn(true);
        ArgumentCaptor<SsoAuditEvent> captor = ArgumentCaptor.forClass(SsoAuditEvent.class);

        service.addEligibleClient(command);

        verify(auditPort).publish(captor.capture());
        SsoAuditEvent event = captor.getValue();
        assertThat(event.getEventType()).isEqualTo(SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_ADDED);
        assertThat(event.getTenant()).isEqualTo(TENANT);
        assertThat(event.getClientId()).isEqualTo(CLIENT_ID);
        assertThat(event.getOutcome()).isEqualTo("ADDED");
        assertThat(event.getOccurredAt()).isEqualTo(Instant.now(CLOCK));
    }

    @Test
    void addEligibleClient_emitsNoOpEvent_whenClientAlreadyExists() {
        AddEligibleClientCommand command = new AddEligibleClientCommand(TENANT, CLIENT_ID);
        when(catalogRepository.addIfAbsent(TENANT, SsoEligibleClient.of(CLIENT_ID))).thenReturn(false);
        ArgumentCaptor<SsoAuditEvent> captor = ArgumentCaptor.forClass(SsoAuditEvent.class);

        service.addEligibleClient(command);

        verify(auditPort).publish(captor.capture());
        SsoAuditEvent event = captor.getValue();
        assertThat(event.getEventType()).isEqualTo(SsoAuditEvent.EventType.SSO_CATALOG_NO_OP);
        assertThat(event.getOutcome()).isEqualTo("ALREADY_EXISTS");
    }

    @Test
    void addEligibleClient_normalizesClientId_beforePersisting() {
        AddEligibleClientCommand command = new AddEligibleClientCommand(TENANT, "  client-x  ");
        when(catalogRepository.addIfAbsent(TENANT, SsoEligibleClient.of(CLIENT_ID))).thenReturn(true);

        service.addEligibleClient(command);

        // El repositorio recibe el clientId normalizado (sin espacios), no el raw del command
        verify(catalogRepository).addIfAbsent(TENANT, SsoEligibleClient.of(CLIENT_ID));
    }

    @Test
    void addEligibleClient_throwsNullPointerException_whenCommandIsNull() {
        assertThatThrownBy(() -> service.addEligibleClient(null))
                .isInstanceOf(NullPointerException.class);
    }

    // =========================================================
    // removeEligibleClient — idempotencia
    // =========================================================

    @Test
    void removeEligibleClient_emitsRemovedEvent_whenClientWasPresent() {
        RemoveEligibleClientCommand command = new RemoveEligibleClientCommand(TENANT, CLIENT_ID);
        when(catalogRepository.removeIfPresent(TENANT, SsoEligibleClient.of(CLIENT_ID))).thenReturn(true);
        ArgumentCaptor<SsoAuditEvent> captor = ArgumentCaptor.forClass(SsoAuditEvent.class);

        service.removeEligibleClient(command);

        verify(auditPort).publish(captor.capture());
        SsoAuditEvent event = captor.getValue();
        assertThat(event.getEventType()).isEqualTo(SsoAuditEvent.EventType.SSO_CATALOG_CLIENT_REMOVED);
        assertThat(event.getTenant()).isEqualTo(TENANT);
        assertThat(event.getClientId()).isEqualTo(CLIENT_ID);
        assertThat(event.getOutcome()).isEqualTo("REMOVED");
    }

    @Test
    void removeEligibleClient_emitsNoOpEvent_whenClientDidNotExist() {
        RemoveEligibleClientCommand command = new RemoveEligibleClientCommand(TENANT, CLIENT_ID);
        when(catalogRepository.removeIfPresent(TENANT, SsoEligibleClient.of(CLIENT_ID))).thenReturn(false);
        ArgumentCaptor<SsoAuditEvent> captor = ArgumentCaptor.forClass(SsoAuditEvent.class);

        service.removeEligibleClient(command);

        verify(auditPort).publish(captor.capture());
        SsoAuditEvent event = captor.getValue();
        assertThat(event.getEventType()).isEqualTo(SsoAuditEvent.EventType.SSO_CATALOG_NO_OP);
        assertThat(event.getOutcome()).isEqualTo("NOT_FOUND");
    }

    @Test
    void removeEligibleClient_normalizesClientId_beforePersisting() {
        RemoveEligibleClientCommand command = new RemoveEligibleClientCommand(TENANT, "  client-x  ");
        when(catalogRepository.removeIfPresent(TENANT, SsoEligibleClient.of(CLIENT_ID))).thenReturn(true);

        service.removeEligibleClient(command);

        verify(catalogRepository).removeIfPresent(TENANT, SsoEligibleClient.of(CLIENT_ID));
    }

    @Test
    void removeEligibleClient_throwsNullPointerException_whenCommandIsNull() {
        assertThatThrownBy(() -> service.removeEligibleClient(null))
                .isInstanceOf(NullPointerException.class);
    }
}
