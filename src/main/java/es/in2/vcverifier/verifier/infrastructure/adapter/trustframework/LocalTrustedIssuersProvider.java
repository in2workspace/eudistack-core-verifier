package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.verifier.domain.service.TrustedIssuersProvider;
import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Resolves trusted issuer capabilities from a local YAML file.
 * If an external filesystem path is configured, reads from there;
 * otherwise falls back to the classpath resource.
 * Supports periodic refresh via {@link #refresh()}.
 */
@Slf4j
public class LocalTrustedIssuersProvider implements TrustedIssuersProvider {

    private static final String CLASSPATH_RESOURCE = "local/trusted-issuers.yaml";
    private final AtomicReference<Map<String, List<IssuerCredentialsCapabilities>>> issuersMapRef = new AtomicReference<>(Collections.emptyMap());
    private final String externalPath;

    public LocalTrustedIssuersProvider() {
        this(null);
    }

    public LocalTrustedIssuersProvider(String externalPath) {
        this.externalPath = externalPath;
        refresh();
    }

    /**
     * Reloads the trusted issuers map from the configured source.
     * Safe to call concurrently — uses AtomicReference for swap.
     */
    public void refresh() {
        ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
        try (InputStream is = openInputStream(externalPath)) {
            if (is == null) {
                log.warn("Local trusted issuers file not found. No issuers will be trusted.");
                issuersMapRef.set(Collections.emptyMap());
                return;
            }
            TrustedIssuersYaml data = yamlMapper.readValue(is, TrustedIssuersYaml.class);
            Map<String, List<IssuerCredentialsCapabilities>> loaded = data.trustedIssuers() != null ? data.trustedIssuers() : Collections.emptyMap();
            issuersMapRef.set(loaded);
            log.info("Loaded {} trusted issuers from local YAML", loaded.size());
        } catch (IOException e) {
            log.error("Failed to reload local trusted issuers YAML, keeping previous version", e);
        }
    }

    private InputStream openInputStream(String externalPath) throws IOException {
        if (externalPath != null && !externalPath.isBlank()) {
            Path path = Path.of(externalPath);
            if (Files.exists(path)) {
                log.debug("Loading trusted issuers from external file: {}", externalPath);
                return new FileInputStream(path.toFile());
            }
            log.warn("External trusted issuers file not found: {}. Falling back to classpath.", externalPath);
        }
        log.debug("Loading trusted issuers from classpath: {}", CLASSPATH_RESOURCE);
        return getClass().getClassLoader().getResourceAsStream(CLASSPATH_RESOURCE);
    }

    @Override
    public List<IssuerCredentialsCapabilities> getIssuerCapabilities(String issuerId) {
        List<IssuerCredentialsCapabilities> capabilities = issuersMapRef.get().get(issuerId);
        if (capabilities == null || capabilities.isEmpty()) {
            throw new IssuerNotAuthorizedException("Issuer with id: " + issuerId + " not found in local trusted issuers.");
        }
        return capabilities;
    }

    private record TrustedIssuersYaml(Map<String, List<IssuerCredentialsCapabilities>> trustedIssuers) {}
}
