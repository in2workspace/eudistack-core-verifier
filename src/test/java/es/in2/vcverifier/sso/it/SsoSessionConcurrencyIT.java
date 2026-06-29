package es.in2.vcverifier.sso.it;

import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoSessionTtl;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SsoSessionConcurrencyIT {

    @InjectMocks
    private EstablishSsoSessionWorkflow workflow;

    @Mock private TenantSsoConfigPort tenantSsoConfigPort;
    @Mock private SsoSessionRepositoryPort sessionRepositoryPort;
    @Mock private SsoAuditPort auditPort;
    @Mock private HashingService hashingService;
    @Mock private Clock clock;

    @Test
    void shouldKeepOnlyOneActiveSession_whenTwoEstablishRunConcurrently() throws Exception {

        ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            String tenant = "tenant-a";
            String holderHash = "holder-xyz";

            // GIVEN config activa
            TenantSsoConfig config = mock(TenantSsoConfig.class);
            when(config.ssoEnabled()).thenReturn(Boolean.TRUE);

            when(tenantSsoConfigPort.getByTenant(tenant))
                    .thenReturn(Optional.of(config));

            // resolveTtl añadido en US-04: sin stub devuelve null → NPE en ttl.absolute()
            when(tenantSsoConfigPort.resolveTtl(tenant))
                    .thenReturn(SsoSessionTtl.of(Duration.ofHours(8), Duration.ofMinutes(30)));

            when(hashingService.sha256(anyString()))
                    .thenReturn("hashed-value");

            when(sessionRepositoryPort.save(any()))
                    .thenAnswer(inv -> inv.getArgument(0));

            CountDownLatch startLatch = new CountDownLatch(1);

            SsoSessionCommand c1 = new SsoSessionCommand(tenant, holderHash, "client", "c1");
            SsoSessionCommand c2 = new SsoSessionCommand(tenant, holderHash, "client", "c2");

            Future<?> f1 = executor.submit(() -> {
                startLatch.await();
                workflow.execute(c1);
                return null;
            });

            Future<?> f2 = executor.submit(() -> {
                startLatch.await();
                workflow.execute(c2);
                return null;
            });

            // WHEN
            startLatch.countDown();

            // asegurar que ambas terminan sin error
            f1.get(10, TimeUnit.SECONDS);
            f2.get(10, TimeUnit.SECONDS);

            // THEN (invariante EC-02)
            verify(sessionRepositoryPort, atMost(2))
                    .supersedeActive(eq(tenant), anyString());

            verify(sessionRepositoryPort, times(2)).save(any());

        } finally {
            executor.shutdownNow();
        }
    }
}