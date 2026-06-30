package es.in2.vcverifier.sso;

import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.workflow.ReuseSsoSessionWorkflowImpl;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.model.SsoTtlRange;
import es.in2.vcverifier.sso.domain.model.TenantSsoCatalog;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import es.in2.vcverifier.sso.domain.service.TenantSsoPolicy;
import es.in2.vcverifier.verifier.application.workflow.ReuseSsoSessionWorkflow.Result;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * IT de componente — valida la integración entre ReuseSsoSessionWorkflowImpl,
 * TenantSsoConfigPort y SsoSession.isValid().
 *
 * No necesita Testcontainers ni Spring: repositorio y config son mocks.
 * El reloj (Clock) también es mock para controlar "now" con precisión.
 *
 * Escenarios:
 *   AC-04: TTL absoluto vencido → LOGIN_REQUIRED
 *   AC-05: TTL idle excedido, TTL absoluto vigente → LOGIN_REQUIRED
 *   EC-02: reducir absoluteTtl en config no invalida sesiones ya activas
 */
@ExtendWith(MockitoExtension.class)
class SsoSessionTtlValidityIT {

    private static final String TENANT      = "tenant-a";
    private static final String CLIENT_ID   = "client-a";
    private static final String HOLDER_HASH = "holder-hash-001";

    @Mock private TenantSsoConfigPort      configPort;
    @Mock private SsoSessionRepositoryPort sessionRepository;
    @Mock private Clock                    clock;
    @Mock private SsoAuditPort             auditPort;
    @Mock private AuthorizationContext     ctx;
    @Mock private RegisteredClientRepository clientRepository;

    // TenantSsoPolicy se construye manualmente para recibir el clock mockeado
    // y que Instant.now(clock) sea el mismo en workflow y policy.
    private ReuseSsoSessionWorkflowImpl workflow;

    // ── Shared config stub: SSO enabled, eligible client ──────────────────────
    private TenantSsoConfig ssoEnabledConfig;

    @BeforeEach
    void setUp() {
        // TenantSsoPolicy usa el mismo clock mock → comparte "now" con el workflow.
        TenantSsoPolicy policy = new TenantSsoPolicy(clientRepository, clock);
        workflow = new ReuseSsoSessionWorkflowImpl(configPort, sessionRepository, clock, auditPort, policy);

        ssoEnabledConfig = new TenantSsoConfig(
                TENANT, "example.com", true,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(8), Duration.ofMinutes(30)),
                List.of(CLIENT_ID)
        );
        when(configPort.getByTenant(anyString())).thenReturn(Optional.of(ssoEnabledConfig));
        // Catálogo siempre contiene el cliente: la validez TTL es la única variable.
        when(configPort.resolveEligibleClients(anyString()))
                .thenReturn(TenantSsoCatalog.of(List.of(CLIENT_ID)));
        // Cliente registrado en el AS: la condición (1) de TenantSsoPolicy siempre pasa.
        when(clientRepository.findByClientId(CLIENT_ID))
                .thenReturn(mock(RegisteredClient.class));
    }

    // =========================================================
    // AC-04: TTL absoluto vencido → LOGIN_REQUIRED
    //
    // La sesión fue creada con absoluteTtl = MIN_ABSOLUTE (5 min).
    // Simulamos "now" = expiresAt + 1s → notExpired = false.
    // =========================================================

    @Test
    void reuse_returnsLoginRequired_whenAbsoluteTtlExpired() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, SsoTtlRange.MIN_ABSOLUTE);

        // now está 1 segundo después de que expira la sesión
        Instant now = session.getExpiresAt().plusSeconds(1);
        when(clock.instant()).thenReturn(now);

        when(configPort.resolveTtl(TENANT))
                .thenReturn(SsoSessionTtl.of(SsoTtlRange.MIN_ABSOLUTE, Duration.ofMinutes(30)));
        when(sessionRepository.findActiveById(any(), anyString()))
                .thenReturn(Optional.of(session));

        Result result = workflow.reuse(TENANT, session.getId().getValue(), ctx, CLIENT_ID);

        assertThat(result.status()).isEqualTo(Result.Status.LOGIN_REQUIRED);
    }

    // =========================================================
    // AC-05: TTL idle excedido, TTL absoluto vigente → LOGIN_REQUIRED
    //
    // La sesión tiene absoluteTtl de 1h; lleva 31 min sin usarse (> idle de 30 min).
    // =========================================================

    @Test
    void reuse_returnsLoginRequired_whenIdleTtlExceeded() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));

        // Simula que la sesión lleva 31 min sin actividad
        Instant now = session.getEstablishedAt().plusSeconds(31 * 60);
        // lastUsedAt = establishedAt (valor inicial de establish())
        // Duration.between(establishedAt, now) = 31 min > idle 30 min → inválida por idle

        when(clock.instant()).thenReturn(now);
        when(configPort.resolveTtl(TENANT))
                .thenReturn(SsoSessionTtl.of(Duration.ofHours(1), Duration.ofMinutes(30)));
        when(sessionRepository.findActiveById(any(), anyString()))
                .thenReturn(Optional.of(session));

        Result result = workflow.reuse(TENANT, session.getId().getValue(), ctx, CLIENT_ID);

        assertThat(result.status()).isEqualTo(Result.Status.LOGIN_REQUIRED);
    }

    @Test
    void reuse_returnsLoginRequired_whenIdleTtlExceededAfterTouch() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(2));

        // Touch a los 10 min; ahora han pasado 41 min desde el touch (> idle 30 min)
        Instant touchAt = session.getEstablishedAt().plusSeconds(10 * 60);
        session.touch(touchAt);

        Instant now = touchAt.plusSeconds(31 * 60);
        when(clock.instant()).thenReturn(now);
        when(configPort.resolveTtl(TENANT))
                .thenReturn(SsoSessionTtl.of(Duration.ofHours(2), Duration.ofMinutes(30)));
        when(sessionRepository.findActiveById(any(), anyString()))
                .thenReturn(Optional.of(session));

        Result result = workflow.reuse(TENANT, session.getId().getValue(), ctx, CLIENT_ID);

        assertThat(result.status()).isEqualTo(Result.Status.LOGIN_REQUIRED);
    }

    // =========================================================
    // EC-02: reducir absoluteTtl en config NO recalcula sesiones vivas
    //
    // La sesión fue establecida con absoluteTtl = 8h (expiresAt = now + 8h).
    // El administrador reduce el config a 5 min.
    //
    // El workflow sólo pasa ttl.idle() a isValid(); la sesión evalúa
    // su propio expiresAt (inmutable). La reducción de config no la afecta.
    // =========================================================

    @Test
    void reuse_returnsAllowed_whenAbsoluteTtlConfigReducedButSessionNotYetExpired() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(8));

        // "now" muy cercano al momento de creación → sesión aún válida en sus propios términos
        Instant now = Instant.now();
        // Aseguramos lastUsedAt dentro del throttle (sin disparo async) usando touch
        session.touch(now);
        when(clock.instant()).thenReturn(now);

        // Config reducida a mínimo absoluto: sería 5 min si se recalculase
        // Pero el workflow usa ttl.absolute() sólo para nuevas sesiones; isValid() sólo usa ttl.idle()
        when(configPort.resolveTtl(TENANT))
                .thenReturn(SsoSessionTtl.of(SsoTtlRange.MIN_ABSOLUTE, Duration.ofMinutes(30)));
        when(sessionRepository.findActiveById(any(), anyString()))
                .thenReturn(Optional.of(session));

        Result result = workflow.reuse(TENANT, session.getId().getValue(), ctx, CLIENT_ID);

        // La sesión sigue siendo ALLOWED porque su expiresAt es now + 8h
        assertThat(result.status()).isEqualTo(Result.Status.ALLOWED);
    }

    @Test
    void reuse_returnsAllowed_whenSessionIsValidExactlyAtIdleBoundary() {
        SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));

        // now = exactamente en el límite idle (30 min); Duration.between(...) = 30 min ≤ 30 min → válido
        Instant now = session.getEstablishedAt().plusSeconds(30 * 60);
        when(clock.instant()).thenReturn(now);
        when(configPort.resolveTtl(TENANT))
                .thenReturn(SsoSessionTtl.of(Duration.ofHours(1), Duration.ofMinutes(30)));
        when(sessionRepository.findActiveById(any(), anyString()))
                .thenReturn(Optional.of(session));

        Result result = workflow.reuse(TENANT, session.getId().getValue(), ctx, CLIENT_ID);

        assertThat(result.status()).isEqualTo(Result.Status.ALLOWED);
    }
}
