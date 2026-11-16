package es.in2.vcverifier.shared.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ReadinessGroupTest {

    /**
     * The readiness group is pinned to the readiness state alone, so the health indicator of the audit outbox, or
     * any other, never takes the Verifier out of rotation because a default changed (PA-08).
     */
    @Test
    void readinessGroup_includesOnlyTheReadinessState() {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application.yaml"));

        Properties properties = yaml.getObject();

        assertEquals("readinessState", properties.getProperty("management.endpoint.health.group.readiness.include"));
    }
}
