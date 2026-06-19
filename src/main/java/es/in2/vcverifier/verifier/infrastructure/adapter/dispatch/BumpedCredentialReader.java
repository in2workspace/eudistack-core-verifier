package es.in2.vcverifier.verifier.infrastructure.adapter.dispatch;

import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
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
public class BumpedCredentialReader implements CredentialReader {

    private final SchemaProfileRegistry schemaProfileRegistry;

    @Override
    public boolean supports(CredentialFormat credentialFormat) {
        return CredentialFormat.BUMPED_V2_0 == credentialFormat;
    }

    @Override
    public ReaderResult read(BuildContext buildContext) {
        String configId = buildContext.dispatchDecision().credentialConfigurationId();
        SchemaProfile schemaProfile = schemaProfileRegistry.findByConfigId(configId)
                .orElseThrow(() -> new InvalidCredentialTypeException("No profile found for: " + configId));

        return new ReaderResult(buildContext.credential(), configId, schemaProfile, true);
    }
}
