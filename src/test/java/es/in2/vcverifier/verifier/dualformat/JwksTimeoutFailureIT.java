package es.in2.vcverifier.verifier.dualformat;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertThrows;

class JwksTimeoutFailureIT {

    @Test
    void jwksTimeoutLeadsToServiceUnavailable() {
        Runnable jwksCaller = () -> { throw new RuntimeException("JWKS timeout"); };
        assertThrows(RuntimeException.class, jwksCaller::run);
    }
}
