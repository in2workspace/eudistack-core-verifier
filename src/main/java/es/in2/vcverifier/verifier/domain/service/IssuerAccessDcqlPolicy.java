package es.in2.vcverifier.verifier.domain.service;

import es.in2.vcverifier.verifier.domain.model.dcql.ClaimQuery;
import es.in2.vcverifier.verifier.domain.model.dcql.CredentialQuery;
import es.in2.vcverifier.verifier.domain.model.dcql.DcqlQuery;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * Pure domain policy that narrows a DCQL query to the credentials able to enter the Issuer console:
 * employee credentials holding either the Onboarding/Execute power or the SysAdmin power.
 * <p>
 * This is a UX filter, not a security boundary: it lets the wallet hide credentials the Issuer would
 * reject anyway. The Issuer keeps enforcing the real check.
 * <p>
 * Each accepted power is emitted as its own credential entry (the wallet unions matches across
 * entries), and the claims of one entry are meant to be satisfied by the same element of
 * {@code mandate.power[]}. The {@code "*"} path segment means "any element of this array".
 */
public final class IssuerAccessDcqlPolicy {

    public static final String ACCESS_PROFILE = "issuer_access";

    private static final String EMPLOYEE_MARKER = "employee";
    private static final String ANY_ELEMENT = "*";
    private static final List<String> SUBJECT_PREFIX_JWT_VC = List.of("credentialSubject");

    private static final List<PowerRequirement> ACCEPTED_POWERS = List.of(
            new PowerRequirement("onboarding_execute", List.of(
                    new PowerField("function", "Onboarding"),
                    new PowerField("action", "Execute"))),
            new PowerRequirement("sysadmin", List.of(
                    new PowerField("type", "organization"),
                    new PowerField("domain", "EUDISTACK"),
                    new PowerField("function", "System"),
                    new PowerField("action", "Administration")))
    );

    private IssuerAccessDcqlPolicy() {
    }

    /**
     * Keeps only the employee credential entries and expands each into one entry per accepted power.
     * Returns the query unchanged when it holds no employee entry, so the login never ends up with an
     * empty query.
     */
    public static DcqlQuery restrict(DcqlQuery query) {
        List<CredentialQuery> restricted = new ArrayList<>();
        for (CredentialQuery entry : query.credentials()) {
            if (isEmployee(entry)) {
                ACCEPTED_POWERS.forEach(power -> restricted.add(withPower(entry, power)));
            }
        }
        return restricted.isEmpty() ? query : new DcqlQuery(restricted);
    }

    private static boolean isEmployee(CredentialQuery entry) {
        if (entry.meta() == null) {
            return false;
        }
        Stream<String> vctValues = entry.meta().vctValues() == null ? Stream.empty() : entry.meta().vctValues().stream();
        Stream<String> types = entry.meta().credentialDefinition() == null || entry.meta().credentialDefinition().type() == null
                ? Stream.empty()
                : entry.meta().credentialDefinition().type().stream();
        return Stream.concat(vctValues, types)
                .anyMatch(value -> value.toLowerCase(Locale.ROOT).contains(EMPLOYEE_MARKER));
    }

    private static CredentialQuery withPower(CredentialQuery entry, PowerRequirement power) {
        List<String> powerPath = new ArrayList<>();
        if (CredentialQuery.FORMAT_JWT_VC_JSON.equals(entry.format())) {
            powerPath.addAll(SUBJECT_PREFIX_JWT_VC);
        }
        powerPath.addAll(List.of("mandate", "power", ANY_ELEMENT));

        List<ClaimQuery> claims = power.fields().stream()
                .map(field -> {
                    List<String> path = new ArrayList<>(powerPath);
                    path.add(field.name());
                    return new ClaimQuery(path, List.of(field.value()), null);
                })
                .toList();
        return new CredentialQuery(entry.id() + "_" + power.idSuffix(), entry.format(), entry.meta(), claims);
    }

    private record PowerRequirement(String idSuffix, List<PowerField> fields) {
    }

    private record PowerField(String name, String value) {
    }
}
