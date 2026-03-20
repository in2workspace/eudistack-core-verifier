package es.in2.vcverifier.shared.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("EUDIStack Verifier API")
                        .version("3.0.0")
                        .description("OID4VP Verifier and OAuth2 Authorization Server"))
                .addServersItem(new Server().url("/").description("Default"));
    }
}
