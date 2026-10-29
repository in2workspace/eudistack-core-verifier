package es.in2.vcverifier.verifier.infrastructure.config;

import es.in2.vcverifier.verifier.domain.model.AssuranceLevel;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class DcqlProfilePropertiesTest {

    private static final String PROFILE = "verifier.dcql.profiles.doctorid.";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class)
            .withPropertyValues(
                    PROFILE + "credentials[0].id=doctorid_sd_jwt",
                    PROFILE + "credentials[0].format=dc+sd-jwt");

    @Test
    void binds_theAssuranceLevelOfAProfile() {
        runner.withPropertyValues(PROFILE + "assurance-level=high")
                .run(context -> assertThat(profile(context).assuranceLevel()).isEqualTo(AssuranceLevel.HIGH));
    }

    @Test
    void binds_noAssuranceLevelWhenTheProfileDeclaresNone() {
        runner.run(context -> assertThat(profile(context).assuranceLevel()).isNull());
    }

    @Test
    void fails_withAnUnknownAssuranceLevel() {
        runner.withPropertyValues(PROFILE + "assurance-level=low")
                .run(context -> assertThat(context).hasFailed());
    }

    private static DcqlProfileProperties.DcqlProfile profile(
            org.springframework.boot.test.context.assertj.AssertableApplicationContext context) {
        return context.getBean(DcqlProfileProperties.class).profiles().get("doctorid");
    }

    @Configuration
    @EnableConfigurationProperties(DcqlProfileProperties.class)
    static class TestConfig {
    }
}
