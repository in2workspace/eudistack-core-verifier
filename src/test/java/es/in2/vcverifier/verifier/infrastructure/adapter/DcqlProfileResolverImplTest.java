package es.in2.vcverifier.verifier.infrastructure.adapter;

import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.infrastructure.config.DcqlProfileProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DcqlProfileResolverImplTest {

    private DcqlProfileResolverImpl resolver;

    @BeforeEach
    void setUp() {
        DcqlProfileProperties properties = new DcqlProfileProperties(Map.of(
                "learcredential.employee", new DcqlProfileProperties.DcqlProfile(List.of(
                        new DcqlProfileProperties.CredentialEntry(
                                "lear_employee_sd_jwt", "dc+sd-jwt",
                                new DcqlProfileProperties.CredentialMeta(
                                        List.of("eu.europa.ec.eudi.lce.1"), null))
                )),
                "learcredential.machine", new DcqlProfileProperties.DcqlProfile(List.of(
                        new DcqlProfileProperties.CredentialEntry(
                                "lear_machine_sd_jwt", "dc+sd-jwt",
                                new DcqlProfileProperties.CredentialMeta(
                                        List.of("eu.europa.ec.eudi.lcm.1"), null)),
                        new DcqlProfileProperties.CredentialEntry(
                                "lear_machine_jwt_vc", "jwt_vc_json",
                                new DcqlProfileProperties.CredentialMeta(
                                        null,
                                        new DcqlProfileProperties.CredentialDefinition(
                                                List.of("VerifiableCredential", "LEARCredentialMachine"))))
                ))
        ));
        resolver = new DcqlProfileResolverImpl(properties);
    }

    @Test
    @DisplayName("resolve() filters OIDC standard scopes and resolves OID4VP scope")
    void resolve_filtersStandardScopes() {
        DcqlQuery result = resolver.resolve("openid profile learcredential.employee");

        assertThat(result.credentials()).hasSize(1);
        assertThat(result.credentials().get(0).id()).isEqualTo("lear_employee_sd_jwt");
        assertThat(result.credentials().get(0).format()).isEqualTo("dc+sd-jwt");
    }

    @Test
    @DisplayName("resolve() merges credentials from multiple OID4VP scopes")
    void resolve_mergesMultipleScopes() {
        DcqlQuery result = resolver.resolve("openid learcredential.employee learcredential.machine");

        assertThat(result.credentials()).hasSize(3);
    }

    @Test
    @DisplayName("resolve() throws when scope string is null")
    void resolve_throwsOnNullScope() {
        assertThatThrownBy(() -> resolver.resolve(null))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessageContaining("empty");
    }

    @Test
    @DisplayName("resolve() throws when scope string is blank")
    void resolve_throwsOnBlankScope() {
        assertThatThrownBy(() -> resolver.resolve("   "))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessageContaining("empty");
    }

    @Test
    @DisplayName("resolve() throws when only OIDC standard scopes are present")
    void resolve_throwsOnOnlyStandardScopes() {
        assertThatThrownBy(() -> resolver.resolve("openid profile email"))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessageContaining("No OID4VP scope found");
    }

    @Test
    @DisplayName("resolve() throws when scope has no matching DCQL profile")
    void resolve_throwsOnUnknownScope() {
        assertThatThrownBy(() -> resolver.resolve("openid unknown.scope"))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessageContaining("No DCQL profile configured for scope 'unknown.scope'");
    }

    @Test
    @DisplayName("resolve() maps meta with credential definition correctly")
    void resolve_mapsCredentialDefinition() {
        DcqlQuery result = resolver.resolve("learcredential.machine");

        var jwtVcQuery = result.credentials().stream()
                .filter(c -> "jwt_vc_json".equals(c.format()))
                .findFirst()
                .orElseThrow();

        assertThat(jwtVcQuery.meta().credentialDefinition().type())
                .containsExactly("VerifiableCredential", "LEARCredentialMachine");
    }

    @Test
    @DisplayName("resolve() maps meta with vct_values correctly")
    void resolve_mapsVctValues() {
        DcqlQuery result = resolver.resolve("learcredential.employee");

        assertThat(result.credentials().get(0).meta().vctValues())
                .containsExactly("eu.europa.ec.eudi.lce.1");
    }

    @Test
    @DisplayName("resolve() works with single OID4VP scope without standard scopes")
    void resolve_singleScopeWithoutStandard() {
        DcqlQuery result = resolver.resolve("learcredential.employee");

        assertThat(result.credentials()).hasSize(1);
    }
}
