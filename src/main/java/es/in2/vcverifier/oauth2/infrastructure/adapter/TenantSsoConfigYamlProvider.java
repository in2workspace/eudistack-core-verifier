package es.in2.vcverifier.oauth2.infrastructure.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.oauth2.domain.exception.SsoConfigLoadingException;
import es.in2.vcverifier.shared.config.properties.BackendProperties;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

@Slf4j
@Component
public class TenantSsoConfigYamlProvider implements TenantSsoConfigProvider {

    private final BackendProperties backendProperties;
    private final ObjectMapper yamlMapper;

    public TenantSsoConfigYamlProvider(BackendProperties backendProperties) {
        this.backendProperties = backendProperties;
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
        log.info("SSO config path = {}", backendProperties.localFiles() != null
                ? backendProperties.localFiles().ssoConfigPath()
                : "NULL");
    }

    @Override
    public TenantSsoConfigYamlData retrieve() {

        try {
            String path = backendProperties.localFiles() != null
                    ? backendProperties.localFiles().ssoConfigPath()
                    : null;

            if (path != null && !path.isBlank()) {
                try (InputStream is = Files.newInputStream(Path.of(path))) {
                    return parseAndNormalize(is);
                } catch (java.nio.file.NoSuchFileException e) {
                    log.warn("sso-config.yaml not found at path: {}. Falling back to classpath.", path);
                }
            }

            InputStream is = getClass().getClassLoader().getResourceAsStream("sso-config.yaml");
            if (is == null) {
                log.warn("sso-config.yaml not found in classpath. Returning empty SSO config.");
                return new TenantSsoConfigYamlData(List.of());
            }

            try (is) {
                return parseAndNormalize(is);
            }

        } catch (Exception e) {
            log.error("Error loading SSO config", e);
            throw new SsoConfigLoadingException("Error loading SSO config", e);
        }
    }

    private TenantSsoConfigYamlData parseAndNormalize(InputStream is) throws Exception {
        TenantSsoConfigYamlData data = yamlMapper.readValue(is, TenantSsoConfigYamlData.class);

        List<TenantSsoEntry> tenants = data.tenants() != null ? data.tenants() : List.of();

        List<TenantSsoEntry> normalized = tenants.stream()
                .map(e -> e.eligibleClients() != null
                        ? e
                        : new TenantSsoEntry(e.tenant(), e.rootDomain(), e.ssoEnabled(), List.of()))
                .toList();

        log.info("ALL TENANTS LOADED = {}", normalized.stream().map(TenantSsoEntry::tenant).toList());

        return new TenantSsoConfigYamlData(normalized);
    }
}
