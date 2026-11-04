package es.in2.vcverifier.oauth2.application.workflow;

import es.in2.vcverifier.oauth2.application.workflow.LoginMethodsWorkflow.LoginMethods;
import es.in2.vcverifier.oauth2.application.workflow.LoginMethodsWorkflow.WalletRequestResult;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestBuildWorkflow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static es.in2.vcverifier.shared.domain.util.Constants.ACCESS_PROFILE;
import static es.in2.vcverifier.shared.domain.util.Constants.ACR_ESSENTIAL;
import static es.in2.vcverifier.shared.domain.util.Constants.ACR_REQUESTED;
import static es.in2.vcverifier.shared.domain.util.Constants.AUTHORIZE_TENANT;
import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.LOGIN_METHODS;
import static es.in2.vcverifier.shared.domain.util.Constants.VP_NONCE;
import static es.in2.vcverifier.shared.domain.util.Constants.WALLET_AUTH_REQUEST;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginMethodsWorkflowTest {

    private static final String STATE = "s-1";
    private static final String TENANT = "cgcom";
    private static final String CLIENT_ID = "issuance-portal";
    private static final String SCOPE = "openid doctorid";
    private static final String HIGH = "http://eidas.europa.eu/LoA/high";
    private static final String AUTH_REQUEST = "openid4vp://?client_id=verifier&request_uri=https://verifier/oid4vp/r/abc";

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;

    @Mock
    private BackendConfig backendConfig;

    private CacheStore<OAuth2AuthorizationRequest> cache;
    private LoginMethodsWorkflow workflow;

    @BeforeEach
    void setUp() {
        cache = new CacheStore<>(10, TimeUnit.MINUTES);
        workflow = new LoginMethodsWorkflow(cache, registeredClientRepository,
                new WalletLoginWorkflow(authorizationRequestBuildWorkflow, backendConfig));
        lenient().when(backendConfig.getLoginTimeoutSeconds()).thenReturn(120L);
    }

    // ---- loginMethods ----

    @Test
    void loginMethods_returnsTheMethodsInTheirOrder() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet")));

        assertThat(workflow.loginMethods(STATE, TENANT))
                .contains(new LoginMethods(List.of("x509", "wallet"), null));
    }

    @Test
    void loginMethods_returnsTheEssentialLevel() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509"), ACR_REQUESTED, HIGH, ACR_ESSENTIAL, true));

        assertThat(workflow.loginMethods(STATE, TENANT)).contains(new LoginMethods(List.of("x509"), HIGH));
    }

    @Test
    void loginMethods_doesNotReturnAPreferredLevel() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet"), ACR_REQUESTED, HIGH, ACR_ESSENTIAL, false));

        assertThat(workflow.loginMethods(STATE, TENANT)).get().extracting(LoginMethods::essentialLevel).isNull();
    }

    @Test
    void loginMethods_ofALoginWithoutMethods_isTheWallet() {
        cacheLogin(Map.of());

        assertThat(workflow.loginMethods(STATE, TENANT)).contains(new LoginMethods(List.of("wallet"), null));
    }

    @Test
    void loginMethods_unknownState_isEmpty() {
        assertThat(workflow.loginMethods("unknown", TENANT)).isEmpty();
    }

    @Test
    void loginMethods_ofAnotherTenant_isEmpty() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet")));

        assertThat(workflow.loginMethods(STATE, "sandbox")).isEmpty();
    }

    @Test
    void loginMethods_ofAnExpiredLogin_isEmpty() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet")), Instant.now().minusSeconds(1));

        assertThat(workflow.loginMethods(STATE, TENANT)).isEmpty();
    }

    // ---- startWallet ----

    @Test
    void startWallet_createsTheWalletRequestAndStoresItInTheLogin() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet"), ACCESS_PROFILE, "issuer_access"));
        RegisteredClient client = registeredClient();
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(client);
        when(authorizationRequestBuildWorkflow.buildAuthorizationRequest(client, SCOPE, STATE, "issuer_access"))
                .thenReturn(new AuthorizationRequestBuildWorkflow.Result("jwt", AUTH_REQUEST, "abc", "vp-nonce"));

        WalletRequestResult result = workflow.startWallet(STATE, TENANT);

        assertThat(result).isInstanceOfSatisfying(WalletRequestResult.Created.class, created -> {
            assertThat(created.authRequest()).isEqualTo(AUTH_REQUEST);
            assertThat(created.expiresIn()).isBetween(119L, 120L);
        });
        Map<String, Object> stored = cache.getIfPresent(STATE).getAdditionalParameters();
        assertThat(stored).containsEntry(VP_NONCE, "vp-nonce").containsEntry(WALLET_AUTH_REQUEST, AUTH_REQUEST);
        assertThat(stored).containsEntry(LOGIN_METHODS, List.of("x509", "wallet"));
    }

    @Test
    void startWallet_startsTheLoginTimeWhenThePersonChoosesTheWallet() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet")), Instant.now().plusSeconds(30));
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient());
        when(authorizationRequestBuildWorkflow.buildAuthorizationRequest(any(), any(), any(), any()))
                .thenReturn(new AuthorizationRequestBuildWorkflow.Result("jwt", AUTH_REQUEST, "abc", "vp-nonce"));

        WalletRequestResult result = workflow.startWallet(STATE, TENANT);

        assertThat(((WalletRequestResult.Created) result).expiresIn()).isBetween(119L, 120L);
        assertThat((Long) cache.getIfPresent(STATE).getAdditionalParameters().get(EXPIRATION))
                .isBetween(Instant.now().plusSeconds(119).getEpochSecond(), Instant.now().plusSeconds(120).getEpochSecond());
    }

    @Test
    void startWallet_calledAgain_keepsTheTimeAlreadySpent() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet"), WALLET_AUTH_REQUEST, AUTH_REQUEST, VP_NONCE, "vp-nonce"),
                Instant.now().plusSeconds(40));
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient());

        WalletRequestResult result = workflow.startWallet(STATE, TENANT);

        assertThat(((WalletRequestResult.Created) result).expiresIn()).isBetween(39L, 40L);
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    @Test
    void startWallet_calledAgain_returnsTheSameRequestWithoutSigningAnother() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet")));
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient());
        when(authorizationRequestBuildWorkflow.buildAuthorizationRequest(any(), any(), any(), any()))
                .thenReturn(new AuthorizationRequestBuildWorkflow.Result("jwt", AUTH_REQUEST, "abc", "vp-nonce"));

        WalletRequestResult first = workflow.startWallet(STATE, TENANT);
        WalletRequestResult second = workflow.startWallet(STATE, TENANT);

        assertThat(((WalletRequestResult.Created) second).authRequest())
                .isEqualTo(((WalletRequestResult.Created) first).authRequest());
        verify(authorizationRequestBuildWorkflow, times(1)).buildAuthorizationRequest(any(), any(), any(), any());
    }

    @Test
    void startWallet_withTheRequestAlreadySignedAtAuthorization_returnsIt() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("wallet"), WALLET_AUTH_REQUEST, AUTH_REQUEST, VP_NONCE, "vp-nonce"));
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(registeredClient());

        WalletRequestResult result = workflow.startWallet(STATE, TENANT);

        assertThat(result).isInstanceOfSatisfying(WalletRequestResult.Created.class,
                created -> assertThat(created.authRequest()).isEqualTo(AUTH_REQUEST));
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    @Test
    void startWallet_loginWithoutTheWallet_isMethodNotOffered() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509")));

        assertThat(workflow.startWallet(STATE, TENANT)).isInstanceOf(WalletRequestResult.MethodNotOffered.class);
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    @Test
    void startWallet_unknownState_isLoginNotFound() {
        assertThat(workflow.startWallet("unknown", TENANT)).isInstanceOf(WalletRequestResult.LoginNotFound.class);
    }

    @Test
    void startWallet_ofAnotherTenant_isLoginNotFound() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet")));

        assertThat(workflow.startWallet(STATE, "sandbox")).isInstanceOf(WalletRequestResult.LoginNotFound.class);
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    @Test
    void startWallet_ofAnExpiredLogin_isLoginNotFound() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet")), Instant.now().minusSeconds(1));

        assertThat(workflow.startWallet(STATE, TENANT)).isInstanceOf(WalletRequestResult.LoginNotFound.class);
    }

    @Test
    void startWallet_clientNoLongerRegistered_isLoginNotFound() {
        cacheLogin(Map.of(LOGIN_METHODS, List.of("x509", "wallet")));

        assertThat(workflow.startWallet(STATE, TENANT)).isInstanceOf(WalletRequestResult.LoginNotFound.class);
        verify(authorizationRequestBuildWorkflow, never()).buildAuthorizationRequest(any(), any(), any(), any());
    }

    private void cacheLogin(Map<String, Object> parameters) {
        cacheLogin(parameters, Instant.now().plusSeconds(120));
    }

    private void cacheLogin(Map<String, Object> parameters, Instant expiration) {
        Map<String, Object> additionalParameters = new HashMap<>(parameters);
        additionalParameters.put(EXPIRATION, expiration.getEpochSecond());
        additionalParameters.put(AUTHORIZE_TENANT, TENANT);
        cache.add(STATE, OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://verifier.example.com/oidc/authorize")
                .clientId(CLIENT_ID)
                .redirectUri("https://portal.example.com/callback")
                .scope(SCOPE)
                .state(STATE)
                .additionalParameters(additionalParameters)
                .build());
    }

    private static RegisteredClient registeredClient() {
        return RegisteredClient.withId(CLIENT_ID)
                .clientId(CLIENT_ID)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://portal.example.com/callback")
                .build();
    }
}
