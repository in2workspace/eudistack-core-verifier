package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;

@Primary
@Component
public class TenantSsoConfigYamlProvider implements TenantSsoConfigProvider {

    @Override
    public TenantSsoConfigYamlData retrieve() {
        try (InputStream is =
                     getClass().getClassLoader().getResourceAsStream("sso-config.yaml")) {

            if (is == null) {
                throw new RuntimeException("sso-config.yaml not found");
            }

            return new Yaml().loadAs(is, TenantSsoConfigYamlData.class);

        } catch (Exception e) {
            throw new RuntimeException("Error loading SSO config", e);
        }
    }
}
