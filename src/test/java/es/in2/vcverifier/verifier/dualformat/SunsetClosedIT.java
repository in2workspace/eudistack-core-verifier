package es.in2.vcverifier.verifier.dualformat;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import es.in2.vcverifier.verifier.domain.exception.LegacyFormatSunsetClosedException;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.ContextAndTypeCredentialSchemaDispatcher;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

class SunsetClosedIT {

    @Test
    void legacyReadDisabledReturns410AndIncrementsMetric() throws Exception {
        TenantConfigPort tenantConfigPort = tenant -> new TenantDomeConfig(false, true);

        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        var dispatcher = new ContextAndTypeCredentialSchemaDispatcher(
                List.of(new DispatchRule("LEARCredentialEmployee.3", CredentialFormat.LEGACY_V1_1)),
                tenantConfigPort,
                registry
        );

        var credential = new DualFormatFlowTestSupport().readFixture("fixtures/dome/employee-3.json");

        assertThrows(LegacyFormatSunsetClosedException.class, () -> dispatcher.dispatch(credential));

        var counter = registry.find("dome_verifier_dispatcher_total")
                .tags("tenant", "unknown", "format", "legacy_v1_1", "decision", "deny", "reason", "LEGACY_SUNSET_CLOSED")
                .counter();

        assertNotNull(counter);
        assertEquals(1.0d, counter.count());
    }
}
