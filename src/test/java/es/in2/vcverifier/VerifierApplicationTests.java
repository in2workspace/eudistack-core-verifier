package es.in2.vcverifier;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
@ActiveProfiles("test")
class VerifierApplicationTests {

    @MockitoBean
    private RegisteredClientRepository registeredClientRepository;

    @Test
    void contextLoads() {
        // The test will automatically fail if the application context cannot be loaded.
    }

    @Test
    void testMain() {
        // Validates the main method exists and is callable.
        // Full context startup is already verified by contextLoads().
        Assertions.assertDoesNotThrow(() ->
                VerifierApplication.class.getMethod("main", String[].class));
    }

}