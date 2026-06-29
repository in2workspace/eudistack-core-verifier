package es.in2.vcverifier.verifier.dualformat;

import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.exception.LegacyFormatSunsetClosedException;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.ContextAndTypeCredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TenantConfigCacheRefreshIT {

    private static final long TTL_MS = 2000L;

    @Test
    void tenantConfigCacheRefreshesAfterTtl() throws Exception {
        AtomicReference<TenantDomeConfig> current = new AtomicReference<>(new TenantDomeConfig(true, true));

        TenantConfigPort underlying = tenant -> current.get();

        TenantConfigPort caching = new CachingTenantConfigPort(underlying, TTL_MS);

        var dispatcher = new ContextAndTypeCredentialSchemaDispatcher(
                List.of(
                        new DispatchRule("LEARCredentialEmployee.3", CredentialFormat.LEGACY_V1_1)
                ),
                caching,
                new SimpleMeterRegistry()
        );

        var credential = new DualFormatFlowTestSupport().readFixture("fixtures/dome/employee-3.json");
        assertDoesNotThrow(() -> dispatcher.dispatch(credential));

        current.set(new TenantDomeConfig(false, true));

        assertDoesNotThrow(() -> dispatcher.dispatch(credential));

        Thread.sleep(TTL_MS + 1000);

        assertThrows(LegacyFormatSunsetClosedException.class, () -> dispatcher.dispatch(credential));
    }

    static class CachingTenantConfigPort implements TenantConfigPort {

        private final TenantConfigPort delegate;
        private final long ttlMillis;

        private volatile TenantDomeConfig cached;
        private volatile long expiresAt = 0L;

        CachingTenantConfigPort(TenantConfigPort delegate, long ttlMillis) {
            this.delegate = delegate;
            this.ttlMillis = ttlMillis;
        }

        @Override
        public TenantDomeConfig getDomeConfig(String tenantDomain) {
            long now = System.currentTimeMillis();
            TenantDomeConfig c = cached;
            if (c == null || now >= expiresAt) {
                synchronized (this) {
                    if (cached == null || now >= expiresAt) {
                        TenantDomeConfig fresh = delegate.getDomeConfig(tenantDomain);
                        cached = fresh;
                        expiresAt = now + ttlMillis;
                    }
                    c = cached;
                }
            }
            return c;
        }
    }
}
