package es.in2.vcverifier.sso.domain;


import es.in2.vcverifier.sso.domain.model.ReuseDecision;
import es.in2.vcverifier.sso.domain.model.TenantSsoPolicy;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.*;

class TenantSsoPolicyTest {

    private final Clock clock = Clock.fixed(
            Instant.parse("2026-01-01T10:00:00Z"),
            ZoneOffset.UTC
    );

    private final TenantSsoPolicy policy = new TenantSsoPolicy(clock, 300); // 5 min TTL

    @Test
    void should_return_ALLOWED_when_session_valid() {

        ReuseDecision result = policy.evaluate(
                "tenant-a",
                "tenant-a",
                Instant.parse("2026-01-01T09:59:00Z"),
                true
        );

        assertEquals(ReuseDecision.ALLOWED, result);
    }

    @Test
    void should_return_NO_SESSION_when_session_is_null() {

        ReuseDecision result = policy.evaluate(
                "tenant-a",
                "tenant-a",
                null,
                true
        );

        assertEquals(ReuseDecision.NO_SESSION, result);
    }

    @Test
    void should_return_SESSION_EXPIRED_when_ttl_exceeded() {

        ReuseDecision result = policy.evaluate(
                "tenant-a",
                "tenant-a",
                Instant.parse("2026-01-01T09:50:00Z"), // > 5 min antes
                true
        );

        assertEquals(ReuseDecision.SESSION_EXPIRED, result);
    }

    @Test
    void should_return_CLIENT_NOT_ELIGIBLE_when_client_not_allowed() {

        ReuseDecision result = policy.evaluate(
                "tenant-a",
                "tenant-a",
                Instant.parse("2026-01-01T09:59:00Z"),
                false
        );

        assertEquals(ReuseDecision.CLIENT_NOT_ELIGIBLE, result);
    }

    @Test
    void should_return_CROSS_TENANT_when_tenants_differ() {

        ReuseDecision result = policy.evaluate(
                "tenant-a",
                "tenant-b",
                Instant.parse("2026-01-01T09:59:00Z"),
                true
        );

        assertEquals(ReuseDecision.CROSS_TENANT, result);
    }
}