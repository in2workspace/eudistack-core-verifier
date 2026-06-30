package es.in2.vcverifier.sso.domain.service;

import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TenantSsoPolicyTest {

    @Mock
    RegisteredClientRepository clientRepository;

    @Mock
    SsoSession session;

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-01-01T10:00:00Z"), ZoneOffset.UTC);
    private static final String CLIENT_ID = "test-client";

    private TenantSsoPolicy policy;
    private SsoSessionTtl ttl;

    @BeforeEach
    void setUp() {
        policy = new TenantSsoPolicy(clientRepository, CLOCK);
        ttl = SsoSessionTtl.systemDefault();
    }

    // =========================================================
    // AC-01: las tres condiciones se cumplen → Allowed
    // =========================================================

    @Test
    void evaluate_returnsAllowed_whenAllConditionsPass() {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(mock(RegisteredClient.class));
        when(session.isValid(any(Instant.class), any())).thenReturn(true);
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_ID));

        TenantSsoPolicy.Decision decision = policy.evaluate(CLIENT_ID, session, ttl, catalog);

        assertThat(decision).isInstanceOf(TenantSsoPolicy.Decision.Allowed.class);
    }

    // =========================================================
    // AC-02: cliente no está en el catálogo → REJECT_CATALOG
    // =========================================================

    @Test
    void evaluate_returnsRejectCatalog_whenClientNotInCatalog() {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(mock(RegisteredClient.class));
        when(session.isValid(any(Instant.class), any())).thenReturn(true);
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of("other-client"));

        TenantSsoPolicy.Decision decision = policy.evaluate(CLIENT_ID, session, ttl, catalog);

        assertThat(decision).isInstanceOfSatisfying(
                TenantSsoPolicy.Decision.Rejected.class,
                rejected -> assertThat(rejected.reason())
                        .isEqualTo(TenantSsoPolicy.RejectReason.REJECT_CATALOG)
        );
    }

    // =========================================================
    // AC-03: catálogo vacío → fail-closed → REJECT_CATALOG
    // =========================================================

    @Test
    void evaluate_returnsRejectCatalog_whenCatalogIsEmpty() {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(mock(RegisteredClient.class));
        when(session.isValid(any(Instant.class), any())).thenReturn(true);
        TenantSsoCatalog catalog = TenantSsoCatalog.empty();

        TenantSsoPolicy.Decision decision = policy.evaluate(CLIENT_ID, session, ttl, catalog);

        assertThat(decision).isInstanceOfSatisfying(
                TenantSsoPolicy.Decision.Rejected.class,
                rejected -> assertThat(rejected.reason())
                        .isEqualTo(TenantSsoPolicy.RejectReason.REJECT_CATALOG)
        );
    }

    // =========================================================
    // AC-05: cliente no registrado en el Authorization Server → REJECT_SESSION
    // =========================================================

    @Test
    void evaluate_returnsRejectSession_whenClientNotRegistered() {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(null);
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_ID));

        TenantSsoPolicy.Decision decision = policy.evaluate(CLIENT_ID, session, ttl, catalog);

        assertThat(decision).isInstanceOfSatisfying(
                TenantSsoPolicy.Decision.Rejected.class,
                rejected -> assertThat(rejected.reason())
                        .isEqualTo(TenantSsoPolicy.RejectReason.REJECT_SESSION)
        );
    }

    // =========================================================
    // EC-01: sesión expirada → REJECT_SESSION (el workflow mapea a login_required)
    // =========================================================

    @Test
    void evaluate_returnsRejectSession_whenSessionHasExpiredAbsoluteTtl() {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(mock(RegisteredClient.class));
        when(session.isValid(any(Instant.class), any())).thenReturn(false);
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_ID));

        TenantSsoPolicy.Decision decision = policy.evaluate(CLIENT_ID, session, ttl, catalog);

        assertThat(decision).isInstanceOfSatisfying(
                TenantSsoPolicy.Decision.Rejected.class,
                rejected -> assertThat(rejected.reason())
                        .isEqualTo(TenantSsoPolicy.RejectReason.REJECT_SESSION)
        );
    }

    @Test
    void evaluate_returnsRejectSession_whenSessionHasExceededIdleTtl() {
        // El mock de isValid() devuelve false tanto para TTL absoluto como para idle;
        // el comportamiento del workflow ante REJECT_SESSION siempre es login_required.
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(mock(RegisteredClient.class));
        when(session.isValid(any(Instant.class), any())).thenReturn(false);
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of(CLIENT_ID));

        TenantSsoPolicy.Decision decision = policy.evaluate(CLIENT_ID, session, ttl, catalog);

        assertThat(decision).isInstanceOfSatisfying(
                TenantSsoPolicy.Decision.Rejected.class,
                rejected -> assertThat(rejected.reason())
                        .isEqualTo(TenantSsoPolicy.RejectReason.REJECT_SESSION)
        );
    }

    // =========================================================
    // EC-03: tenant legacy (sin clientes elegibles configurados) → fail-closed
    //
    // Un tenant legacy (SSO no habilitado o sin config) produce un catálogo vacío
    // en TenantSsoConfigPort.resolveEligibleClients(). La policy debe rechazar
    // aunque el cliente esté registrado y la sesión sea válida.
    // =========================================================

    @Test
    void evaluate_returnsRejectCatalog_forLegacyTenantWithNoCatalogConfig() {
        when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(mock(RegisteredClient.class));
        when(session.isValid(any(Instant.class), any())).thenReturn(true);
        TenantSsoCatalog emptyCatalog = TenantSsoCatalog.empty(); // tenant sin SSO catalog

        TenantSsoPolicy.Decision decision = policy.evaluate(CLIENT_ID, session, ttl, emptyCatalog);

        assertThat(decision).isInstanceOfSatisfying(
                TenantSsoPolicy.Decision.Rejected.class,
                rejected -> assertThat(rejected.reason())
                        .isEqualTo(TenantSsoPolicy.RejectReason.REJECT_CATALOG)
        );
    }

    // =========================================================
    // NFR-S-550-01: entradas null lanzan NPE (fail-safe explícito)
    // =========================================================

    @Test
    void evaluate_throwsNullPointerException_whenClientIdIsNull() {
        assertThatThrownBy(() -> policy.evaluate(null, session, ttl, TenantSsoCatalog.empty()))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void evaluate_throwsNullPointerException_whenSessionIsNull() {
        assertThatThrownBy(() -> policy.evaluate(CLIENT_ID, null, ttl, TenantSsoCatalog.empty()))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void evaluate_throwsNullPointerException_whenTtlIsNull() {
        assertThatThrownBy(() -> policy.evaluate(CLIENT_ID, session, null, TenantSsoCatalog.empty()))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void evaluate_throwsNullPointerException_whenCatalogIsNull() {
        assertThatThrownBy(() -> policy.evaluate(CLIENT_ID, session, ttl, null))
                .isInstanceOf(NullPointerException.class);
    }
}
