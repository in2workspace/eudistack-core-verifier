package es.in2.vcverifier.verifier.domain.port;

import es.in2.vcverifier.shared.domain.model.LoginMethod;

import java.util.Set;

public interface TenantLoginMethodsPort {

    Set<LoginMethod> activeLoginMethods(String tenant);
}
