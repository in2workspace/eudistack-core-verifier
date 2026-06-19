package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;
import es.in2.vcverifier.verifier.domain.model.tokens.ReaderResult;

public interface CredentialReader {
    boolean supports(CredentialFormat credentialFormat);
    ReaderResult read(BuildContext buildContext);
}
