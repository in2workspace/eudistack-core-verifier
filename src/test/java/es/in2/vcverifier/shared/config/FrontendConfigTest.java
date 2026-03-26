package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.FrontendProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FrontendConfigImplTest {

    @InjectMocks
    private FrontendConfig frontendConfig;

    @Mock
    private FrontendProperties frontendProperties;

    @Test
    void testGetPortalUrl_ReturnsConfiguredPortalUrl() {
        when(frontendProperties.portalUrl()).thenReturn("https://login-stg.altia.eudistack.net");

        assertThat(frontendConfig.getPortalUrl()).isEqualTo("https://login-stg.altia.eudistack.net");
    }
}
