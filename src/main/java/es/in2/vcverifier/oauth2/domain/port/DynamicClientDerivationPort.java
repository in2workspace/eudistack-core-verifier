package es.in2.vcverifier.oauth2.domain.port;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.oauth2.domain.model.DerivedClientCredentials;

public interface DynamicClientDerivationPort {

    DerivedClientCredentials derive(JsonNode validatedCredential);

}
