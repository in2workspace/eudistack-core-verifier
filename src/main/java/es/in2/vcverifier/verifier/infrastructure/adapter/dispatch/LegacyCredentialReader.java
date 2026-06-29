package es.in2.vcverifier.verifier.infrastructure.adapter.dispatch;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;
import es.in2.vcverifier.verifier.domain.model.tokens.ReaderResult;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.CredentialReader;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class LegacyCredentialReader implements CredentialReader {

    private final SchemaProfileRegistry schemaProfileRegistry;

    @Override
    public boolean supports(CredentialFormat credentialFormat) {
        return CredentialFormat.LEGACY_V1_1 == credentialFormat;
    }

    @Override
    public ReaderResult read(BuildContext buildContext) {
        JsonNode credential = buildContext.credential();
        JsonNode wrappedVc = credential.get("vc");
        JsonNode payload = wrappedVc != null && !wrappedVc.isNull() ? wrappedVc : credential;

        String configId = buildContext.dispatchDecision().credentialConfigurationId();
        SchemaProfile schemaProfile = schemaProfileRegistry.findByConfigId(configId).orElse(null);

        return new ReaderResult(payload, configId, schemaProfile, false);
    }
}
