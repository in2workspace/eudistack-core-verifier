package es.in2.vcverifier.shared.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("EUDIStack Core Verifier")
                        .description("OID4VP Verifier — European Digital Identity credential verification service")
                        .version("3.0.0"));
    }
}
