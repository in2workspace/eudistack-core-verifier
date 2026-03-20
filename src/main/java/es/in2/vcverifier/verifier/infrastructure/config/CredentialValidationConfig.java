package es.in2.vcverifier.verifier.infrastructure.config;

import es.in2.vcverifier.shared.config.VerifierConfig;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.SdJwtVerificationService;
import es.in2.vcverifier.shared.crypto.SdJwtVerificationServiceImpl;
import es.in2.vcverifier.verifier.domain.service.ClaimsExtractor;
import es.in2.vcverifier.verifier.domain.service.CredentialSchemaResolver;
import es.in2.vcverifier.verifier.domain.service.CredentialValidator;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import es.in2.vcverifier.verifier.domain.service.TrustFrameworkService;
import es.in2.vcverifier.verifier.infrastructure.adapter.claims.SchemaProfileClaimsExtractor;
import es.in2.vcverifier.verifier.infrastructure.adapter.schema.JsonSchemaCredentialValidator;
import es.in2.vcverifier.verifier.infrastructure.adapter.schema.LocalSchemaProfileRegistry;
import es.in2.vcverifier.verifier.infrastructure.adapter.schema.LocalSchemaResolver;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Slf4j
@Configuration
public class CredentialValidationConfig {

    @Bean
    public CredentialSchemaResolver localSchemaResolver(VerifierConfig verifierConfig) {
        log.info("Registering Local Schema Resolver");
        return new LocalSchemaResolver(verifierConfig.getLocalSchemasDir());
    }

    @Bean
    public CredentialValidator credentialValidator(List<CredentialSchemaResolver> resolvers) {
        log.info("Registering JSON Schema Credential Validator with {} resolvers", resolvers.size());
        return new JsonSchemaCredentialValidator(resolvers);
    }

    @Bean
    public SchemaProfileRegistry schemaProfileRegistry(VerifierConfig verifierConfig) {
        log.info("Registering Schema Profile Registry");
        return new LocalSchemaProfileRegistry(verifierConfig.getLocalSchemasDir());
    }

    @Bean
    public ClaimsExtractor schemaProfileClaimsExtractor(SchemaProfileRegistry schemaProfileRegistry, com.fasterxml.jackson.databind.ObjectMapper objectMapper) {
        log.info("Registering Schema Profile Claims Extractor");
        return new SchemaProfileClaimsExtractor(schemaProfileRegistry, objectMapper);
    }

    @Bean
    public SdJwtVerificationService sdJwtVerificationService(DIDService didService, TrustFrameworkService trustFrameworkService, MeterRegistry meterRegistry) {
        log.info("Registering SD-JWT Verification Service");
        return new SdJwtVerificationServiceImpl(didService, trustFrameworkService, meterRegistry);
    }
}
