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
    }

    @Override
    public es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData retrieve() {

        try {
            String path = backendProperties.localFiles() != null
                    ? backendProperties.localFiles().ssoConfigPath()
                    : null;

            // Caso 1: no configurado → devolver vacío
            if (path == null || path.isBlank()) {
                log.warn("ssoConfigPath not configured. Returning empty SSO config.");
                return new es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData(List.of());
            }

            // Caso 2: leer desde filesystem
            try (InputStream is = Files.newInputStream(Path.of(path))) {

                TenantSsoConfigYamlData infraData =
                        yamlMapper.readValue(is, TenantSsoConfigYamlData.class);

                List<TenantSsoEntry> domainEntries =
                        infraData.tenants()
                                .stream()
                                .map(e -> new TenantSsoEntry(
                                        e.tenant(),
                                        e.rootDomain(),
                                        e.ssoEnabled()
                                ))
                                .toList();

                return new es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData(domainEntries);
            }

        } catch (Exception e) {
            log.error("Error loading SSO config", e);
            throw new SsoConfigLoadingException("Error loading SSO config", e);
        }
    }


}


