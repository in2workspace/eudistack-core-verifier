package es.in2.vcverifier.verifier.dualformat;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertTrue;

class DispatchRuleCatalogConsistencyTest {

    @Test
    void eachCredentialConfigIdIsDeclaredInDispatchRules() throws IOException {
        var support = new DualFormatFlowTestSupport();
        List<Path> fixtures = Files.list(Path.of("src/test/resources/fixtures/dome")).collect(Collectors.toList());

        Set<String> declared = Set.of(
                "LEARCredentialEmployee.3",
                "LEARCredentialMachine.2",
                "gx:LabelCredential.1",
                "LEARCredentialEmployee.4",
                "LEARCredentialMachine.3",
                "gx:LabelCredential.2"
        );

        for (Path p : fixtures) {
            var node = support.readFixture("fixtures/dome/" + p.getFileName().toString());
            if (node.has("credential_configuration_id")) {
                String cid = node.get("credential_configuration_id").asText();
                assertTrue(declared.contains(cid), "Fixture contains undeclared credential_configuration_id: " + cid);
            }
        }
    }
}
