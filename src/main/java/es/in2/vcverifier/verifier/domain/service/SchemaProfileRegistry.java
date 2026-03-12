package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;

import java.util.Optional;

public interface SchemaProfileRegistry {
    Optional<SchemaProfile> findByConfigId(String credentialConfigurationId);
    boolean hasProfile(String credentialConfigurationId);
}
