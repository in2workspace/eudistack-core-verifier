package es.in2.vcverifier.oauth2.infrastructure.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.oauth2.domain.exception.SsoConfigLoadingException;
import es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.config.properties.BackendProperties;
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
    public es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData retrieve() {

        try {
            String path = backendProperties.localFiles() != null
                    ? backendProperties.localFiles().ssoConfigPath()
                    : null;

            // Caso 1: ruta externa configurada → leer desde filesystem
            if (path != null && !path.isBlank()) {
                try (InputStream is = Files.newInputStream(Path.of(path))) {
                    return parseAndMap(is);
                } catch (java.nio.file.NoSuchFileException e) {
                    log.warn("sso-config.yaml not found at path: {}. Falling back to classpath.", path);
                }
            }

            // Caso 2: sin ruta externa → intentar classpath
            InputStream is = getClass().getClassLoader().getResourceAsStream("sso-config.yaml");
            if (is == null) {
                log.warn("sso-config.yaml not found in classpath. Returning empty SSO config.");
                return new es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData(List.of());
            }

            try (is) {
                return parseAndMap(is);
            }

        } catch (Exception e) {
            log.error("Error loading SSO config", e);
            throw new SsoConfigLoadingException("Error loading SSO config", e);
        }
    }

    private es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData parseAndMap(InputStream is) throws Exception {
        TenantSsoConfigYamlData infraData = yamlMapper.readValue(is, TenantSsoConfigYamlData.class);

        log.info("ALL TENANTS LOADED = {}",
                infraData.tenants().stream().map(TenantSsoEntry::tenant).toList());

        List<TenantSsoEntry> domainEntries = infraData.tenants()
                .stream()
                .map(e -> new TenantSsoEntry(
                        e.tenant(),
                        e.rootDomain(),
                        e.ssoEnabled(),
                        e.eligibleClients() != null ? e.eligibleClients() : List.of(),
                        e.ttlAbsolute(),
                        e.ttlIdle()
                ))
                .toList();

        return new es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData(domainEntries);
    }


}


