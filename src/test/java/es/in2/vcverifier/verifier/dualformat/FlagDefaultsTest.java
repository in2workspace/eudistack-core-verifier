package es.in2.vcverifier.verifier.dualformat;

import es.in2.vcverifier.shared.config.properties.DispatchProperties;
import es.in2.vcverifier.shared.config.properties.TenantDomeConfigProperties;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = FlagDefaultsTest.TestConfig.class)
class FlagDefaultsTest {

    @Autowired
    private DispatchProperties dispatchProperties;

    @Autowired
    private TenantDomeConfigProperties tenantDomeConfigProperties;

    @Test
    void defaultsAreLoadedFromApplicationYaml() {
        assertThat(tenantDomeConfigProperties.legacyReadEnabledOrDefault()).isTrue();
        assertThat(tenantDomeConfigProperties.bumpedReadEnabledOrDefault()).isTrue();

        assertThat(dispatchProperties.legacyRules()).hasSize(3);
        assertThat(dispatchProperties.bumpedRules()).hasSize(3);
        assertThat(dispatchProperties.allRules()).hasSize(6);

        assertThat(dispatchProperties.legacyRules())
                .anySatisfy(rule -> {
                    assertThat(rule.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.3");
                    assertThat(rule.format()).isEqualTo(CredentialFormat.LEGACY_V1_1);
                });

        assertThat(dispatchProperties.bumpedRules())
                .anySatisfy(rule -> {
                    assertThat(rule.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
                    assertThat(rule.format()).isEqualTo(CredentialFormat.BUMPED_V2_0);
                });
    }

    @EnableConfigurationProperties({DispatchProperties.class, TenantDomeConfigProperties.class})
    static class TestConfig {
    }
}
