package es.in2.vcverifier.verifier.dualformat;

import org.junit.jupiter.api.Test;

import es.in2.vcverifier.verifier.domain.exception.UnknownCredentialFormatException;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.ContextAndTypeCredentialSchemaDispatcher;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

class AllowlistPreservationIT {

    @Test
    void unknownRpIsRejectedSameAsPreMigration() throws Exception {
        TenantConfigPort tenantConfigPort = tenant -> new TenantDomeConfig(true, true);

        var dispatcher = new ContextAndTypeCredentialSchemaDispatcher(
                List.of(
                        new DispatchRule("LEARCredentialEmployee.3", CredentialFormat.LEGACY_V1_1)
                ),
                tenantConfigPort,
                new SimpleMeterRegistry()
        );

        var credential = new DualFormatFlowTestSupport().readFixture("fixtures/dome/label-1.json");

        assertThrows(UnknownCredentialFormatException.class, () -> dispatcher.dispatch(credential));
    }
}
