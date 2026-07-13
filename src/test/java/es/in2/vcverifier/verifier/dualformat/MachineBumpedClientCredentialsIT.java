package es.in2.vcverifier.verifier.dualformat;

import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import org.junit.jupiter.api.Test;

class MachineBumpedClientCredentialsIT {

    private final DualFormatFlowTestSupport support = new DualFormatFlowTestSupport();

    @Test
    void bumpedMachineCredentialIsDispatchedAndTokenizedForM2M() throws Exception {
        var credential = support.readFixture("fixtures/dome/machine-3.json");
        var result = support.runFlow(credential);

        support.assertHappyPath(result, "LEARCredentialMachine.3", CredentialFormat.BUMPED_V2_0);
    }
}
