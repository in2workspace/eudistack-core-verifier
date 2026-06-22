package es.in2.vcverifier.verifier.application.workflow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.domain.service.VpService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VerifyPresentationWorkflowTest {

    @Mock
    private VpService vpService;

    @Mock
    private CredentialSchemaDispatcher credentialSchemaDispatcher;

    @InjectMocks
    private VerifyPresentationWorkflow workflow;

    private static final String VP_TOKEN = "eyJhbGciOiJFUzI1NiJ9.test.signature";

    @Test
    @DisplayName("execute() validates VP and returns extracted credential")
    void execute_validatesAndExtractsCredential() {
        JsonNode expectedCredential = new ObjectMapper().createObjectNode().put("type", "LEARCredentialEmployee");
        DispatchDecision dispatchDecision = DispatchDecision.permitted(
                "learcredential.employee.w3c.4",
                CredentialFormat.BUMPED_V2_0,
                DispatchReason.BY_TYPE
        );
        when(vpService.extractCredentialFromVerifiablePresentationAsJsonNode(VP_TOKEN)).thenReturn(expectedCredential);
        when(credentialSchemaDispatcher.dispatch(expectedCredential)).thenReturn(dispatchDecision);

        VerifyPresentationWorkflow.Result result = workflow.verifyPresentation(VP_TOKEN);

        assertThat(result.credential()).isEqualTo(expectedCredential);
        assertThat(result.dispatchDecision()).isEqualTo(dispatchDecision);
        verify(vpService).verifyVerifiablePresentation(VP_TOKEN);
        verify(vpService).extractCredentialFromVerifiablePresentationAsJsonNode(VP_TOKEN);
        verify(credentialSchemaDispatcher).dispatch(expectedCredential);
    }

    @Test
    @DisplayName("execute() propagates exception when VP validation fails")
    void execute_propagatesExceptionWhenValidationFails() {
        doThrow(new RuntimeException("Invalid VP")).when(vpService).verifyVerifiablePresentation(VP_TOKEN);

        assertThatThrownBy(() -> workflow.verifyPresentation(VP_TOKEN))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid VP");

        verify(vpService).verifyVerifiablePresentation(VP_TOKEN);
        verify(vpService, never()).extractCredentialFromVerifiablePresentationAsJsonNode(any());
    }
}
