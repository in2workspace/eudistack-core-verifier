package es.in2.vcverifier.verifier.dualformat;

import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import org.junit.jupiter.api.Test;

class BumpedEmployeeDispatchIT {

    private final DualFormatFlowTestSupport support = new DualFormatFlowTestSupport();

    @Test
    void bumpedEmployeeCredentialIsDispatchedAndTokenizedWithVcWrap() throws Exception {
        var credential = support.readFixture("fixtures/dome/employee-4.json");
        var result = support.runFlow(credential);

        support.assertHappyPath(result, "LEARCredentialEmployee.4", CredentialFormat.BUMPED_V2_0);
    }
}
