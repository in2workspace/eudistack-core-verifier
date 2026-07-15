package es.in2.vcverifier.verifier.dualformat;

import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class LegacyAllTypesDispatchIT {

    private final DualFormatFlowTestSupport support = new DualFormatFlowTestSupport();

    @ParameterizedTest
    @CsvSource({
            "fixtures/dome/employee-3.json, LEARCredentialEmployee.3",
            "fixtures/dome/machine-2.json, LEARCredentialMachine.2",
            "fixtures/dome/label-1.json, gx:LabelCredential.1"
    })
    void allLegacyTypesAreDispatchedToLegacyReader(String fixturePath, String expectedCredentialType) throws Exception {
        var credential = support.readFixture(fixturePath);
        var result = support.runFlow(credential);

        support.assertHappyPath(result, expectedCredentialType, CredentialFormat.LEGACY_V1_1);
    }
}
