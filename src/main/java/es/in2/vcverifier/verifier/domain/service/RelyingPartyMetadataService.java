package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.oid4vp.ClientMetadata;
import java.util.Optional;

public interface RelyingPartyMetadataService {
    Optional<ClientMetadata> getMetadataByClientId(String clientId);
}
