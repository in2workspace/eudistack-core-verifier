package es.in2.vcverifier.shared.infrastructure.audit;

import com.eudistack.auditoria.domain.ActorKind;
import com.eudistack.auditoria.domain.AuditContext;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerifierAuditContextResolverTest {

    private final VerifierAuditContextResolver resolver = new VerifierAuditContextResolver();

    private static MockHttpServletRequest requestOf(String tenant) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (tenant != null) {
            request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, tenant);
        }
        return request;
    }

    @Test
    void resolve_authenticatedClient_isASystemNamedByTheClient() {
        // Arrange
        var client = new UsernamePasswordAuthenticationToken("client-7", "n/a", List.of());

        // Act
        Optional<AuditContext> context = resolver.resolve(requestOf("sandbox"), client);

        // Assert
        assertEquals("sandbox", context.orElseThrow().tenant());
        assertEquals(ActorKind.SYSTEM, context.orElseThrow().actor().kind());
        assertEquals("client-7", context.orElseThrow().actor().id());
    }

    @Test
    void resolve_noAuthentication_isTheVerifierItself() {
        // Arrange & Act
        Optional<AuditContext> context = resolver.resolve(requestOf("sandbox"), null);

        // Assert
        assertEquals("verifier", context.orElseThrow().actor().id());
    }

    @Test
    void resolve_anonymousAuthentication_isTheVerifierItself() {
        // Arrange
        var anonymous = new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        // Act
        Optional<AuditContext> context = resolver.resolve(requestOf("sandbox"), anonymous);

        // Assert
        assertEquals("verifier", context.orElseThrow().actor().id());
    }

    @Test
    void resolve_requestWithoutTenant_hasNoContext() {
        // Arrange & Act
        Optional<AuditContext> context = resolver.resolve(requestOf(null), null);

        // Assert
        assertTrue(context.isEmpty());
    }
}
