package es.in2.vcverifier.verifier.dualformat;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import es.in2.vcverifier.verifier.domain.exception.BumpedFormatTemporarilyDisabledException;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.ContextAndTypeCredentialSchemaDispatcher;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

class BumpedDisabledIT {

    @Test
    void bumpedDisabledReturns503() throws Exception {
        TenantConfigPort tenantConfigPort = tenant -> new TenantDomeConfig(true, false);

        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        var dispatcher = new ContextAndTypeCredentialSchemaDispatcher(
                List.of(new DispatchRule("LEARCredentialEmployee.4", CredentialFormat.BUMPED_V2_0)),
                tenantConfigPort,
                registry
        );

        var credential = new DualFormatFlowTestSupport().readFixture("fixtures/dome/employee-4.json");

        assertThrows(BumpedFormatTemporarilyDisabledException.class, () -> dispatcher.dispatch(credential));

        var counter = registry.find("dome_verifier_dispatcher_total")
                .tags("tenant", "default", "format", "bumped_v2_0", "decision", "deny", "reason", "BUMPED_DISABLED")
                .counter();

        assertNotNull(counter);
        assertEquals(1.0d, counter.count());
    }
}
