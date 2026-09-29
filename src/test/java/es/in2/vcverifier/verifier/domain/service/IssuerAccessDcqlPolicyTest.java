package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.dcql.ClaimQuery;
import es.in2.vcverifier.verifier.domain.model.dcql.CredentialQuery;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

class IssuerAccessDcqlPolicyTest {

    private static CredentialQuery employeeSdJwt() {
        return new CredentialQuery("lear_employee_sd_jwt", CredentialQuery.FORMAT_DC_SD_JWT,
                new CredentialQuery.CredentialMeta(List.of("learcredential.employee.sd.1"), null), null);
    }

    private static CredentialQuery machineSdJwt() {
        return new CredentialQuery("lear_machine_sd_jwt", CredentialQuery.FORMAT_DC_SD_JWT,
                new CredentialQuery.CredentialMeta(List.of("learcredential.machine.sd.1"), null), null);
    }

    private static CredentialQuery employeeJwtVc() {
        return new CredentialQuery("lear_employee_jwt_vc", CredentialQuery.FORMAT_JWT_VC_JSON,
                new CredentialQuery.CredentialMeta(null, new CredentialQuery.CredentialDefinition(
                        List.of("VerifiableCredential", "learcredential.employee.w3c.4"))), null);
    }

    private static CredentialQuery legacyEmployeeJwtVc() {
        return new CredentialQuery("lear_employee_jwt_vc_legacy", CredentialQuery.FORMAT_JWT_VC_JSON,
                new CredentialQuery.CredentialMeta(null, new CredentialQuery.CredentialDefinition(
                        List.of("VerifiableCredential", "LEARCredentialEmployee"))), null);
    }

    private static CredentialQuery machineJwtVc() {
        return new CredentialQuery("lear_machine_jwt_vc", CredentialQuery.FORMAT_JWT_VC_JSON,
                new CredentialQuery.CredentialMeta(null, new CredentialQuery.CredentialDefinition(
                        List.of("VerifiableCredential", "learcredential.machine.w3c.3"))), null);
    }

    @Test
    @DisplayName("restrict() drops machine credential entries")
    void restrict_dropsMachineEntries() {
        // Arrange
        DcqlQuery query = new DcqlQuery(List.of(employeeSdJwt(), machineSdJwt(), machineJwtVc()));

        // Act
        DcqlQuery result = IssuerAccessDcqlPolicy.restrict(query);

        // Assert
        assertThat(result.credentials()).extracting(CredentialQuery::id)
                .hasSize(2)
                .noneMatch(id -> id.contains("machine"));
    }

    @Test
    @DisplayName("restrict() expands each employee entry into an Onboarding/Execute and a SysAdmin entry")
    void restrict_expandsEachEmployeeEntryIntoOneEntryPerAcceptedPower() {
        // Arrange
        DcqlQuery query = new DcqlQuery(List.of(employeeSdJwt(), employeeJwtVc()));

        // Act
        DcqlQuery result = IssuerAccessDcqlPolicy.restrict(query);

        // Assert
        assertThat(result.credentials()).extracting(CredentialQuery::id).containsExactly(
                "lear_employee_sd_jwt_onboarding_execute",
                "lear_employee_sd_jwt_sysadmin",
                "lear_employee_jwt_vc_onboarding_execute",
                "lear_employee_jwt_vc_sysadmin");
    }

    @Test
    @DisplayName("restrict() keeps the original format and meta of the employee entry")
    void restrict_keepsFormatAndMeta() {
        // Arrange
        CredentialQuery employee = employeeSdJwt();

        // Act
        DcqlQuery result = IssuerAccessDcqlPolicy.restrict(new DcqlQuery(List.of(employee)));

        // Assert
        assertThat(result.credentials())
                .hasSize(2)
                .allSatisfy(entry -> {
                    assertThat(entry.format()).isEqualTo(employee.format());
                    assertThat(entry.meta()).isEqualTo(employee.meta());
                });
    }

    @Test
    @DisplayName("restrict() requires Onboarding and Execute on mandate.power[] for dc+sd-jwt without a credentialSubject prefix")
    void restrict_sdJwtOnboardingExecuteClaims() {
        // Arrange
        DcqlQuery query = new DcqlQuery(List.of(employeeSdJwt()));

        // Act
        CredentialQuery onboarding = IssuerAccessDcqlPolicy.restrict(query).credentials().get(0);

        // Assert
        assertThat(onboarding.claims()).extracting(ClaimQuery::path, ClaimQuery::values).containsExactly(
                tuple(List.of("mandate", "power", "*", "function"), List.of("Onboarding")),
                tuple(List.of("mandate", "power", "*", "action"), List.of("Execute")));
    }

    @Test
    @DisplayName("restrict() requires the four SysAdmin fields on mandate.power[]")
    void restrict_sdJwtSysAdminClaims() {
        // Arrange
        DcqlQuery query = new DcqlQuery(List.of(employeeSdJwt()));

        // Act
        CredentialQuery sysAdmin = IssuerAccessDcqlPolicy.restrict(query).credentials().get(1);

        // Assert
        assertThat(sysAdmin.claims()).extracting(ClaimQuery::path, ClaimQuery::values).containsExactly(
                tuple(List.of("mandate", "power", "*", "type"), List.of("organization")),
                tuple(List.of("mandate", "power", "*", "domain"), List.of("EUDISTACK")),
                tuple(List.of("mandate", "power", "*", "function"), List.of("System")),
                tuple(List.of("mandate", "power", "*", "action"), List.of("Administration")));
    }

    @Test
    @DisplayName("restrict() prefixes claim paths with credentialSubject for jwt_vc_json")
    void restrict_jwtVcClaimsUseCredentialSubjectPrefix() {
        // Arrange
        DcqlQuery query = new DcqlQuery(List.of(employeeJwtVc()));

        // Act
        CredentialQuery onboarding = IssuerAccessDcqlPolicy.restrict(query).credentials().get(0);

        // Assert
        assertThat(onboarding.claims()).extracting(ClaimQuery::path).containsExactly(
                List.of("credentialSubject", "mandate", "power", "*", "function"),
                List.of("credentialSubject", "mandate", "power", "*", "action"));
    }

    @Test
    @DisplayName("restrict() recognises the legacy LEARCredentialEmployee type case-insensitively")
    void restrict_recognisesLegacyEmployeeType() {
        // Arrange
        DcqlQuery query = new DcqlQuery(List.of(legacyEmployeeJwtVc()));

        // Act
        DcqlQuery result = IssuerAccessDcqlPolicy.restrict(query);

        // Assert
        assertThat(result.credentials()).extracting(CredentialQuery::id).containsExactly(
                "lear_employee_jwt_vc_legacy_onboarding_execute",
                "lear_employee_jwt_vc_legacy_sysadmin");
    }

    @Test
    @DisplayName("restrict() returns the query unchanged when it has no employee entry")
    void restrict_returnsQueryUnchangedWhenNoEmployeeEntry() {
        // Arrange
        DcqlQuery query = new DcqlQuery(List.of(machineSdJwt(), machineJwtVc()));

        // Act
        DcqlQuery result = IssuerAccessDcqlPolicy.restrict(query);

        // Assert
        assertThat(result).isSameAs(query);
    }

    @Test
    @DisplayName("restrict() ignores entries without meta")
    void restrict_ignoresEntriesWithoutMeta() {
        // Arrange
        CredentialQuery noMeta = new CredentialQuery("no_meta", CredentialQuery.FORMAT_DC_SD_JWT, null, null);
        DcqlQuery query = new DcqlQuery(List.of(noMeta, employeeSdJwt()));

        // Act
        DcqlQuery result = IssuerAccessDcqlPolicy.restrict(query);

        // Assert
        assertThat(result.credentials()).extracting(CredentialQuery::id)
                .hasSize(2)
                .noneMatch(id -> id.startsWith("no_meta"));
    }
}
