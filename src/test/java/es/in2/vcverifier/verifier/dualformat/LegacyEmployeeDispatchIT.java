package es.in2.vcverifier.verifier.dualformat;

import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.LegacyCredentialReader;
import org.junit.jupiter.api.Test;

class LegacyEmployeeDispatchIT {

    private final DualFormatFlowTestSupport support = new DualFormatFlowTestSupport();

    @Test
    void legacyEmployeeCredentialIsDispatchedAndTokenized() throws Exception {
        var credential = support.readFixture("fixtures/dome/employee-3.json");
        var result = support.runFlow(credential);

        DualFormatFlowTestSupport.assertReaderClass(result, LegacyCredentialReader.class);
        support.assertHappyPath(result, "LEARCredentialEmployee.3", CredentialFormat.LEGACY_V1_1, false);
    }
}
