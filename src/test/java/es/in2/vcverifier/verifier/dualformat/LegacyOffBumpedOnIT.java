package es.in2.vcverifier.verifier.dualformat;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.ContextAndTypeCredentialSchemaDispatcher;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

class LegacyOffBumpedOnIT {

    @Test
    void bumpedStillPermittedWhenLegacyOff() throws Exception {
        TenantConfigPort tenantConfigPort = tenant -> new TenantDomeConfig(false, true);

        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        var dispatcher = new ContextAndTypeCredentialSchemaDispatcher(
                List.of(new DispatchRule("LEARCredentialEmployee.4", CredentialFormat.BUMPED_V2_0)),
                tenantConfigPort,
                registry
        );

        var credential = new DualFormatFlowTestSupport().readFixture("fixtures/dome/employee-4.json");

        assertDoesNotThrow(() -> dispatcher.dispatch(credential));
        var decision = dispatcher.dispatch(credential);
        assertEquals(CredentialFormat.BUMPED_V2_0, decision.format());
    }
}
