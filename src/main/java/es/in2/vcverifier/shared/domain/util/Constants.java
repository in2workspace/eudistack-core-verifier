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
    public static final String SESSION_EXPIRED = "session_expired";
    public static final String LOG_ERROR_FORMAT = "{} - {}";
    public static final String OID4VP_TYPE = "oauth-authz-req+jwt";
    // US-06 [W3]: OIDC Back-Channel Logout 1.0 §2.4/§5 RECOMMENDS typ=logout+jwt to prevent
    // token-type confusion, since the same EC key signs id_token/access_token/logout_token.
    public static final String LOGOUT_JWT_TYPE = "logout+jwt";
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
    // Carries the original login's auth_time (epoch seconds) across a refresh_token grant so the
    // new id_token reuses it instead of stamping "now" — see RefreshTokenDataCache.
    public static final String AUTH_TIME_PARAM = "auth_time";
    // EUD-252: SHA-256 (hex) of the __Host-sso-tx browser-binding cookie set at /authorize, kept in
    // the cached OAuth2AuthorizationRequest so the cross-device close step can prove the browser
    // that finishes the login is the one that started it.
    public static final String BROWSER_BINDING_HASH = "browser_binding_hash";
    // EUD-252 (F1): the OID4VP nonce of the login, kept in the same cached OAuth2AuthorizationRequest
    // entry as everything else so request and nonce are always written together, atomically, by the
    // same /authorize call. Distinct from the client's OIDC "nonce".
    public static final String VP_NONCE = "vp_nonce";
    // EUD-252 (F1): tenant resolved at /authorize; the wallet POST must come through the same tenant.
    public static final String AUTHORIZE_TENANT = "authorize_tenant";
    // EUD-252: browser-side close of a cross-device login (establishes the SSO session in the
    // browser that started the login, then redirects to the RP). Relative to the context path.
    public static final String LOGIN_COMPLETION_PATH = "/api/login/complete";

}
