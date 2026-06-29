package es.in2.vcverifier.verifier.dualformat;

import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.LegacyCredentialReader;
import org.junit.jupiter.api.Test;

class MachineLegacyClientCredentialsIT {

    private final DualFormatFlowTestSupport support = new DualFormatFlowTestSupport();

    @Test
    void legacyMachineCredentialIsDispatchedAndTokenizedForM2M() throws Exception {
        var credential = support.readFixture("fixtures/dome/machine-2.json");
        var result = support.runFlow(credential);

        DualFormatFlowTestSupport.assertReaderClass(result, LegacyCredentialReader.class);
        support.assertHappyPath(result, "LEARCredentialMachine.2", CredentialFormat.LEGACY_V1_1, false);
    }
}
