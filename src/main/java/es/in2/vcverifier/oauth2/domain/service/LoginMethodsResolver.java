package es.in2.vcverifier.oauth2.domain.service;

import es.in2.vcverifier.oauth2.domain.model.RequestedAssuranceLevel;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.LoginMethod;

import java.util.List;
import java.util.Set;

public final class LoginMethodsResolver {

    private static final AssuranceLevel CERTIFICATE_LEVEL = AssuranceLevel.HIGH;

    public List<LoginMethod> resolve(List<LoginMethod> clientMethods, Set<LoginMethod> tenantMethods,
                                     AssuranceLevel walletLevel, RequestedAssuranceLevel requestedLevel) {
        List<LoginMethod> available = clientMethods.stream()
                .filter(tenantMethods::contains)
                .toList();
        if (requestedLevel == null) {
            return available;
        }
        List<LoginMethod> meetingLevel = available.stream()
                .filter(method -> meetsLevel(method, walletLevel, requestedLevel.level()))
                .toList();
        if (meetingLevel.isEmpty() && !requestedLevel.essential()) {
            return available;
        }
        return meetingLevel;
    }

    private static boolean meetsLevel(LoginMethod method, AssuranceLevel walletLevel, AssuranceLevel requested) {
        return switch (method) {
            case WALLET -> walletLevel != null && walletLevel.satisfies(requested);
            case X509 -> CERTIFICATE_LEVEL.satisfies(requested);
        };
    }
}
