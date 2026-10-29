package es.in2.vcverifier.shared.domain.model.audit;

/**
 * A third-party system the Verifier calls, as the {@code ExternalSystemAccess} event describes it.
 *
 * @param systemType           catalogue {@code system_type}
 * @param system               registered name or host of the third party
 * @param authenticationMethod catalogue {@code authentication_method}
 */
public record ExternalSystemTarget(String systemType, String system, String authenticationMethod) {

    public static final String AUTHENTICATION_NONE = "None";

    public static ExternalSystemTarget trustedList(String system) {
        return new ExternalSystemTarget("TrustedList", system, AUTHENTICATION_NONE);
    }

    public static ExternalSystemTarget clientRegistry(String system) {
        return new ExternalSystemTarget("ClientRegistry", system, AUTHENTICATION_NONE);
    }
}
