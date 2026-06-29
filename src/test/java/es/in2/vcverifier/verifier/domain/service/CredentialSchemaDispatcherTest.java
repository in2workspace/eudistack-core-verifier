package es.in2.vcverifier.verifier.domain.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import es.in2.vcverifier.verifier.domain.exception.UnknownCredentialFormatException;
import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.ContextAndTypeCredentialSchemaDispatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialSchemaDispatcherTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock
    private TenantConfigPort tenantConfigPort;

    private ContextAndTypeCredentialSchemaDispatcher dispatcher;

    @BeforeEach
    void setUp() {
        List<DispatchRule> dispatchRules = List.of(
                new DispatchRule("LEARCredentialEmployee.3", CredentialFormat.LEGACY_V1_1),
                new DispatchRule("LEARCredentialMachine.2", CredentialFormat.LEGACY_V1_1),
                new DispatchRule("gx:LabelCredential.1", CredentialFormat.LEGACY_V1_1),
                new DispatchRule("LEARCredentialEmployee.4", CredentialFormat.BUMPED_V2_0),
                new DispatchRule("LEARCredentialMachine.3", CredentialFormat.BUMPED_V2_0),
                new DispatchRule("gx:LabelCredential.2", CredentialFormat.BUMPED_V2_0)
        );

        lenient().when(tenantConfigPort.getDomeConfig(anyString())).thenReturn(new TenantDomeConfig(true, true));
        dispatcher = new ContextAndTypeCredentialSchemaDispatcher(
                dispatchRules,
                tenantConfigPort,
                new SimpleMeterRegistry()
        );
    }

    @Test
    void dispatch_mixedContext_resolvesByType() {
        ObjectNode credential = credentialWithType("LEARCredentialEmployee.4");
        ArrayNode mixedContext = MAPPER.createArrayNode();
        mixedContext.add("https://www.w3.org/2018/credentials/v1");
        mixedContext.add("https://www.w3.org/ns/credentials/v2");
        credential.set("@context", mixedContext);

        DispatchDecision result = dispatcher.dispatch(credential);

        assertEquals("LEARCredentialEmployee.4", result.credentialConfigurationId());
        assertEquals(CredentialFormat.BUMPED_V2_0, result.format());
        assertEquals(DispatchReason.BY_TYPE_CONTEXT_MISMATCH, result.reason());
        assertTrue(result.permitted());
    }

    @Test
    void dispatch_withoutKnownVcdmContext_resolvesByType() {
        ObjectNode credential = credentialWithType("LEARCredentialEmployee.4");
        ArrayNode customContext = MAPPER.createArrayNode();
        customContext.add("https://dome.example/custom-context-only");
        credential.set("@context", customContext);

        DispatchDecision result = dispatcher.dispatch(credential);

        assertEquals("LEARCredentialEmployee.4", result.credentialConfigurationId());
        assertEquals(CredentialFormat.BUMPED_V2_0, result.format());
        assertEquals(DispatchReason.BY_TYPE, result.reason());
        assertTrue(result.permitted());
    }

    @Test
    void dispatch_typeOrderNonCanonical_stillResolves() {
        ObjectNode credential = MAPPER.createObjectNode();
        credential.putArray("@context").add("https://www.w3.org/2018/credentials/v1");
        credential.putArray("type")
                .add("LEARCredentialEmployee.3")
                .add("VerifiableCredential");

        DispatchDecision result = dispatcher.dispatch(credential);

        assertEquals("LEARCredentialEmployee.3", result.credentialConfigurationId());
        assertEquals(CredentialFormat.LEGACY_V1_1, result.format());
        assertTrue(result.permitted());
    }

    @Test
    void dispatch_contextMissingAndNoType_throwsUnknownCredentialFormatException() {
        ObjectNode credential = MAPPER.createObjectNode();
        credential.put("id", "urn:uuid:test");

        assertThrows(UnknownCredentialFormatException.class, () -> dispatcher.dispatch(credential));
    }

    @Test
    void dispatch_onlyGenericTypes_throwsUnknownCredentialFormatException() {
        ObjectNode credential = MAPPER.createObjectNode();
        credential.putArray("@context").add("https://www.w3.org/2018/credentials/v1");
        credential.putArray("type")
                .add("VerifiableCredential")
                .add("VerifiableAttestation");

        assertThrows(UnknownCredentialFormatException.class, () -> dispatcher.dispatch(credential));
    }

    @Test
    void dispatch_unknownConfigId_throwsUnknownCredentialFormatException() {
        ObjectNode credential = credentialWithType("UnknownCredential.999");

        assertThrows(UnknownCredentialFormatException.class, () -> dispatcher.dispatch(credential));
    }

    @Test
    void dispatch_noTypeButKnownContext_failsSecure() {
        ObjectNode credential = MAPPER.createObjectNode();
        credential.putArray("@context").add("https://www.w3.org/ns/credentials/v2");

        assertThrows(UnknownCredentialFormatException.class, () -> dispatcher.dispatch(credential));
    }

    private ObjectNode credentialWithType(String configId) {
        ObjectNode credential = MAPPER.createObjectNode();
        credential.putArray("@context").add("https://www.w3.org/ns/credentials/v2");
        credential.putArray("type")
                .add("VerifiableCredential")
                .add(configId);
        return credential;
    }
}
