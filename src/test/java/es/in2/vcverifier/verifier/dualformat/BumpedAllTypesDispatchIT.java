package es.in2.vcverifier.verifier.dualformat;

import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class BumpedAllTypesDispatchIT {

    private final DualFormatFlowTestSupport support = new DualFormatFlowTestSupport();

    @ParameterizedTest
    @CsvSource({
            "fixtures/dome/employee-4.json, LEARCredentialEmployee.4",
            "fixtures/dome/machine-3.json, LEARCredentialMachine.3",
            "fixtures/dome/label-2.json, gx:LabelCredential.2"
    })
    void allBumpedTypesAreDispatchedToBumpedReader(String fixturePath, String expectedCredentialType) throws Exception {
        var credential = support.readFixture(fixturePath);
        var result = support.runFlow(credential);

        support.assertHappyPath(result, expectedCredentialType, CredentialFormat.BUMPED_V2_0);
    }
}
