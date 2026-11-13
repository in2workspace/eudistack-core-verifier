package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import es.in2.vcverifier.verifier.infrastructure.config.DcqlProfileProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
                ), null),
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
                ), null)
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
    @DisplayName("resolve() ignores the identification number scope of the certificate login")
    void resolve_ignoresTheIdentificationNumberScope() {
        DcqlQuery result = resolver.resolve("openid profile personal_administrative_number learcredential.employee");

        assertThat(result.credentials()).hasSize(1);
        assertThat(result.credentials().get(0).id()).isEqualTo("lear_employee_sd_jwt");
    }

    @Test
    @DisplayName("resolve() finds no attestation when only the identification number scope is requested")
    void resolve_throwsWhenOnlyTheIdentificationNumberScopeIsRequested() {
        assertThatThrownBy(() -> resolver.resolve("openid personal_administrative_number"))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessageContaining("No OID4VP scope found");
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

    @Test
    @DisplayName("highestAssuranceLevel() returns the highest level among the profiles of the scopes")
    void highestAssuranceLevel_returnsTheHighestLevel() {
        DcqlProfileResolverImpl leveled = resolverWithLevels(Map.of(
                "learcredential", AssuranceLevel.SUBSTANTIAL,
                "doctorid", AssuranceLevel.HIGH));

        assertThat(leveled.highestAssuranceLevel(List.of("openid", "learcredential", "doctorid")))
                .contains(AssuranceLevel.HIGH);
    }

    @Test
    @DisplayName("highestAssuranceLevel() ignores the profiles that declare no level")
    void highestAssuranceLevel_ignoresProfilesWithoutLevel() {
        DcqlProfileResolverImpl leveled = resolverWithLevels(Map.of("learcredential", AssuranceLevel.SUBSTANTIAL));

        assertThat(leveled.highestAssuranceLevel(List.of("learcredential", "learcredential.employee")))
                .contains(AssuranceLevel.SUBSTANTIAL);
    }

    @Test
    @DisplayName("highestAssuranceLevel() is empty when no profile of the scopes declares a level")
    void highestAssuranceLevel_isEmptyWithoutLevels() {
        assertThat(resolver.highestAssuranceLevel(List.of("learcredential.employee", "learcredential.machine")))
                .isEmpty();
    }

    @Test
    @DisplayName("highestAssuranceLevel() ignores scopes without a DCQL profile instead of failing")
    void highestAssuranceLevel_ignoresScopesWithoutProfile() {
        DcqlProfileResolverImpl leveled = resolverWithLevels(Map.of("doctorid", AssuranceLevel.HIGH));

        assertThat(leveled.highestAssuranceLevel(List.of("openid", "personal_administrative_number", "doctorid")))
                .contains(AssuranceLevel.HIGH);
        assertThat(leveled.highestAssuranceLevel(List.of("openid", "personal_administrative_number")))
                .isEmpty();
    }

    @Test
    @DisplayName("highestAssuranceLevel() is empty without scopes")
    void highestAssuranceLevel_isEmptyWithoutScopes() {
        assertThat(resolver.highestAssuranceLevel(null)).isEmpty();
        assertThat(resolver.highestAssuranceLevel(List.of())).isEmpty();
    }

    @Test
    @DisplayName("assuranceLevelOf() returns the level of the profile the presented SD-JWT matches by vct")
    void assuranceLevelOf_sdJwt_returnsTheLevelOfTheMatchingProfile() {
        DcqlProfileResolverImpl leveled = resolverWithLevels(Map.of(
                "learcredential", AssuranceLevel.SUBSTANTIAL,
                "doctorid", AssuranceLevel.HIGH));
        ObjectNode credential = JsonNodeFactory.instance.objectNode().put("vct", "learcredential.1");

        assertThat(leveled.assuranceLevelOf(List.of("openid", "learcredential", "doctorid"), credential))
                .contains(AssuranceLevel.SUBSTANTIAL);
    }

    @Test
    @DisplayName("assuranceLevelOf() reads the scopes of an authorization request kept as one space-separated value")
    void assuranceLevelOf_splitsTheScopeOfTheAuthorizationRequest() {
        DcqlProfileResolverImpl leveled = resolverWithLevels(Map.of("learcredential", AssuranceLevel.SUBSTANTIAL));
        ObjectNode credential = JsonNodeFactory.instance.objectNode().put("vct", "learcredential.1");

        assertThat(leveled.assuranceLevelOf(Set.of("openid learcredential"), credential))
                .contains(AssuranceLevel.SUBSTANTIAL);
        assertThat(leveled.highestAssuranceLevel(Set.of("openid  learcredential "))).contains(AssuranceLevel.SUBSTANTIAL);
    }

    @Test
    @DisplayName("assuranceLevelOf() matches a W3C credential when it has every type of the credential definition")
    void assuranceLevelOf_w3c_matchesByCredentialDefinitionTypes() {
        DcqlProfileResolverImpl leveled = new DcqlProfileResolverImpl(new DcqlProfileProperties(Map.of(
                "learcredential", new DcqlProfileProperties.DcqlProfile(List.of(
                        new DcqlProfileProperties.CredentialEntry("lear_jwt_vc", "jwt_vc_json",
                                new DcqlProfileProperties.CredentialMeta(null,
                                        new DcqlProfileProperties.CredentialDefinition(
                                                List.of("VerifiableCredential", "learcredential.employee.w3c.4"))))),
                        AssuranceLevel.SUBSTANTIAL))));
        ObjectNode employee = JsonNodeFactory.instance.objectNode();
        employee.putArray("type").add("VerifiableCredential").add("learcredential.employee.w3c.4");
        ObjectNode other = JsonNodeFactory.instance.objectNode();
        other.putArray("type").add("VerifiableCredential").add("gx.labelcredential.w3c.2");

        assertThat(leveled.assuranceLevelOf(List.of("learcredential"), employee)).contains(AssuranceLevel.SUBSTANTIAL);
        assertThat(leveled.assuranceLevelOf(List.of("learcredential"), other)).isEmpty();
    }

    @Test
    @DisplayName("assuranceLevelOf() is empty when the matching profile declares no level or nothing matches")
    void assuranceLevelOf_isEmptyWithoutAMatchingLeveledProfile() {
        DcqlProfileResolverImpl leveled = resolverWithLevels(Map.of("doctorid", AssuranceLevel.HIGH));

        assertThat(leveled.assuranceLevelOf(List.of("doctorid"),
                JsonNodeFactory.instance.objectNode().put("vct", "learcredential.1"))).isEmpty();
        assertThat(resolver.assuranceLevelOf(List.of("learcredential.employee"),
                JsonNodeFactory.instance.objectNode().put("vct", "learcredential.employee.sd.1"))).isEmpty();
        assertThat(leveled.assuranceLevelOf(null, JsonNodeFactory.instance.objectNode())).isEmpty();
    }

    @Test
    @DisplayName("requestsAttestation() is true only when a scope has a DCQL profile")
    void requestsAttestation_isTrueOnlyForScopesWithAProfile() {
        assertThat(resolver.requestsAttestation(List.of("openid", "learcredential.employee"))).isTrue();
        assertThat(resolver.requestsAttestation(List.of("openid", "profile", "personal_administrative_number"))).isFalse();
        assertThat(resolver.requestsAttestation(null)).isFalse();
    }

    private static DcqlProfileResolverImpl resolverWithLevels(Map<String, AssuranceLevel> levels) {
        Map<String, DcqlProfileProperties.DcqlProfile> profiles = new HashMap<>();
        levels.forEach((scope, level) -> profiles.put(scope, new DcqlProfileProperties.DcqlProfile(List.of(
                new DcqlProfileProperties.CredentialEntry(scope + "_sd_jwt", "dc+sd-jwt",
                        new DcqlProfileProperties.CredentialMeta(List.of(scope + ".1"), null))), level)));
        profiles.put("learcredential.employee", new DcqlProfileProperties.DcqlProfile(List.of(), null));
        return new DcqlProfileResolverImpl(new DcqlProfileProperties(profiles));
    }
}
