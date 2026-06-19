package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;

public interface AccessTokenBuilder {
    String build(BuildContext buildContext);
}
