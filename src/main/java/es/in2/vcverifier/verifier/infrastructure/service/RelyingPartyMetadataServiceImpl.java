package es.in2.vcverifier.verifier.infrastructure.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.verifier.domain.model.oid4vp.ClientMetadata;
import es.in2.vcverifier.verifier.domain.service.RelyingPartyMetadataService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;

@Service
public class RelyingPartyMetadataServiceImpl implements RelyingPartyMetadataService {

    private static final Logger log = LoggerFactory.getLogger(RelyingPartyMetadataServiceImpl.class);
    private final ObjectMapper objectMapper;
    private Map<String, ClientMetadata> metadataMap = new HashMap<>();

    public RelyingPartyMetadataServiceImpl(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void init() {
        try {
            Resource resource = new ClassPathResource("relying-party-metadata.json");
            if (resource.exists()) {
                TypeReference<Map<String, ClientMetadata>> typeRef = new TypeReference<>() {};
                metadataMap = objectMapper.readValue(resource.getInputStream(), typeRef);
                log.info("Loaded {} relying party metadata entries from JSON", metadataMap.size());
            } else {
                log.warn("Relying Party Metadata file not found in resources");
            }
        } catch (IOException e) {
            log.error("Error loading relying party metadata: {}", e.getMessage());
            metadataMap = new HashMap<>();
        }
    }

    @Override
    public Optional<ClientMetadata> getMetadataByClientId(String clientId) {
        return Optional.ofNullable(metadataMap.get(clientId))
                .map(rpMetadata -> rpMetadata.withVpFormatsSupported(
                        ClientMetadata.defaultMetadata().vpFormatsSupported()
                ));
    }
}


