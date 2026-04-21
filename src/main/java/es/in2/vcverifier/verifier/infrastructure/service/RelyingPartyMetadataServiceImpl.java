package es.in2.vcverifier.verifier.infrastructure.service;

import es.in2.vcverifier.verifier.domain.model.oid4vp.ClientMetadata;
import es.in2.vcverifier.verifier.domain.service.RelyingPartyMetadataService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class RelyingPartyMetadataServiceImpl implements RelyingPartyMetadataService {

    private static final Map<String, ClientMetadata> RP_STORAGE = Map.of(
            "https://verifier.cgcom.es", new ClientMetadata(
                    null,
                    "Consejo General de Colegios Oficiales de Médicos",
                    "",
                    "",
                    "",
                    "",
                    List.of("contacto@cgcom.es"),
                    Map.of(
                            "client_name#es", "Consejo General de Médicos",
                            "client_name#en", "General Council of Medical Colleges"
                    )
            )
    );

    @Override
    public Optional<ClientMetadata> getMetadataByClientId(String clientId) {
        return Optional.ofNullable(RP_STORAGE.get(clientId))
                .map(rpMetadata -> rpMetadata.withVpFormatsSupported(
                        ClientMetadata.defaultMetadata().vpFormatsSupported()
                ));
    }
}


