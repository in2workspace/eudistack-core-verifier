package es.in2.vcverifier.shared.domain.util;

public class Constants {
    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    public static final String CLIENT_ID = "client_id";
    public static final String REQUEST_URI = "request_uri";
    public static final String REQUEST = "request";
    public static final String RESPONSE_TYPE= "response_type";
    public static final String SCOPE = "scope";
    public static final String AUTHORIZATION_RESPONSE_ENDPOINT= "/oid4vp/auth-response";
    public static final String DID_ELSI_PREFIX = "did:elsi:";
    public static final String MINUTES = "MINUTES";
    public static final String REQUIRED_EXTERNAL_USER_AUTHENTICATION = "required_external_user_authentication";
    public static final String INVALID_CLIENT_AUTHENTICATION = "invalid_client_authentication";
    public static final String LOGIN_REQUIRED = "login_required";
    public static final String INTERACTION_REQUIRED = "interaction_required";
    public static final String LOG_ERROR_FORMAT = "{} - {}";
    public static final String OID4VP_TYPE = "oauth-authz-req+jwt";
    public static final long MSB = 0x80L;
    public static final long MSBALL = 0xFFFFFF80L;
    public static final String EXPIRATION = "expiration";
    public static final String REVOCATION = "revocation";
    public static final String CLIENT_SETTING_TENANT = "settings.tenant";
    public static final String CLIENT_SETTING_LOGIN_PAGE_URI = "settings.login_page_uri";
    public static final String CLIENT_SETTING_CLIENT_METADATA = "settings.clientMetadata";
    // US-06 Single Logout (AD-4/DELTA-01): backchannel_logout_uri declarado por el RP,
    // fuente primaria del BackchannelLogoutUriPort.
    public static final String CLIENT_SETTING_BACKCHANNEL_LOGOUT_URI = "settings.backchannelLogoutUri";
    // JTI cache TTL: 2x access token lifetime (900s) to ensure replay window coverage
    public static final long JTI_CACHE_TTL_SECONDS = 1800L;
    public static final String X_TENANT_HEADER = "X-Tenant";

}
