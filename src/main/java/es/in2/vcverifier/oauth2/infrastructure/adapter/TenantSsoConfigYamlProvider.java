package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;
import java.io.InputStream;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TenantSsoConfigYamlProvider implements TenantSsoConfigProvider {

    @Override
    public es.in2.vcverifier.shared.domain.port.TenantSsoConfigYamlData retrieve() {
        try (InputStream is =
                     getClass().getClassLoader().getResourceAsStream("sso-config.yaml")) {

            if (is == null) {
                throw new SsoConfigLoadingException("sso-config.yaml not found");
            }

            TenantSsoConfigYamlData infraData = new Yaml().loadAs(is, TenantSsoConfigYamlData.class);

            // Convert infrastructure model to domain model
            List<es.in2.vcverifier.shared.domain.port.TenantSsoEntry> domainEntries = infraData.tenants().stream()
                    .map(e -> new es.in2.vcverifier.shared.domain.port.TenantSsoEntry(e.tenant(), e.rootDomain(), e.ssoEnabled()))
                    .collect(Collectors.toList());

            return new es.in2.vcverifier.shared.domain.port.TenantSsoConfigYamlData(domainEntries);

        } catch (SsoConfigLoadingException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error loading SSO config", e);
            throw new SsoConfigLoadingException("Error loading SSO config", e);
        }
    }

    /**
     * Domain exception for SSO config loading failures.
     */
    public static class SsoConfigLoadingException extends RuntimeException {
        public SsoConfigLoadingException(String message) {
            super(message);
        }

        public SsoConfigLoadingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}


