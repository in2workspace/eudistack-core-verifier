package es.in2.vcverifier.verifier.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.domain.service.VpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Application workflow that validates a Verifiable Presentation and extracts
 * the embedded credential as a JsonNode.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class VerifyPresentationWorkflow {

    private final VpService vpService;
    private final CredentialSchemaDispatcher credentialSchemaDispatcher;

    public record Result(
            JsonNode credential,
            DispatchDecision dispatchDecision
    ) {
    }

    /**
     * Validates the VP and returns the embedded credential.
     *
     * @param vpToken the raw VP JWT string
     * @return credential + dispatch decision
     */
    public Result verifyPresentation(String vpToken) {
        log.info("VerifyPresentationWorkflow: validating VP");
        vpService.verifyVerifiablePresentation(vpToken);
        JsonNode credential = vpService.extractCredentialFromVerifiablePresentationAsJsonNode(vpToken);
        DispatchDecision dispatchDecision = credentialSchemaDispatcher.dispatch(credential);
        log.info("VerifyPresentationWorkflow: VP validated, credential extracted and dispatched");
        return new Result(credential, dispatchDecision);
    }
}
