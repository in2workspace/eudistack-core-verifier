package es.in2.vcverifier.sso.it;

/*
import es.in2.vcverifier.sso.application.command.SsoSessionCommand;
import es.in2.vcverifier.sso.application.workflow.EstablishSsoSessionWorkflow;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.port.SsoSessionRepositoryPort;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * EC-02:
 * Invariante: como máximo 1 sesión ACTIVE por (tenant, holderHash)
 *
 * Escenario:
 * 2 establishes concurrentes para el mismo usuario → debe quedar 1 ACTIVE
 */


/*
@SpringBootTest
@ActiveProfiles("test")
class SsoSessionConcurrencyIT {

    @Autowired
    private EstablishSsoSessionWorkflow workflow;

    @Autowired
    private SsoSessionRepositoryPort repository;

    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    @Test
    void shouldKeepOnlyOneActiveSession_whenTwoEstablishRunConcurrently() throws Exception {

        String tenant = "tenant-a";
        String holderHash = "holder-xyz";
        String clientId = "client-test";

        SsoSessionCommand cmd1 = new SsoSessionCommand(tenant, holderHash, clientId, "corr-1");
        SsoSessionCommand cmd2 = new SsoSessionCommand(tenant, holderHash, clientId, "corr-2");

        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch finishLatch = new CountDownLatch(2);

        List<Future<SsoSession>> results = new ArrayList<>();

        results.add(executor.submit(() -> {
            startLatch.await();
            try {
                return workflow.execute(cmd1);
            } finally {
                finishLatch.countDown();
            }
        }));

        results.add(executor.submit(() -> {
            startLatch.await();
            try {
                return workflow.execute(cmd2);
            } finally {
                finishLatch.countDown();
            }
        }));

        // Start both at same time
        startLatch.countDown();

        // wait completion
        finishLatch.await(10, TimeUnit.SECONDS);

        // ensure both completed without exception
        for (Future<SsoSession> f : results) {
            assertDoesNotThrow(f::get);
        }

        // validate invariant in DB / repository
        List<SsoSession> activeSessions = findActiveSessionsDirectly(tenant, holderHash);

        assertEquals(1, activeSessions.size(),
                "Invariant violated: more than one ACTIVE session exists");

        assertEquals("ACTIVE", activeSessions.get(0).getState().name());
    }

    /**
     * Helper: acceso directo al repositorio para validar estado final.
     * (en test real podrías usar query directa o método repo adicional)
     */
/*
    private List<SsoSession> findActiveSessionsDirectly(String tenant, String holderHash) {

        List<SsoSession> result = new ArrayList<>();

        repository.findActiveByTenantAndHolder(tenant, holderHash)
                .ifPresent(result::add);

        return result;
    }
}



*/