package es.in2.vcverifier.oauth2.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.model.LoginMethod;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static es.in2.vcverifier.shared.domain.util.Constants.ACCESS_PROFILE;
import static es.in2.vcverifier.shared.domain.util.Constants.ACR_ESSENTIAL;
import static es.in2.vcverifier.shared.domain.util.Constants.ACR_REQUESTED;
import static es.in2.vcverifier.shared.domain.util.Constants.AUTHORIZE_TENANT;
import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.LOGIN_METHODS;
import static es.in2.vcverifier.shared.domain.util.Constants.WALLET_AUTH_REQUEST;
import static es.in2.vcverifier.shared.domain.util.LogSanitizer.sanitize;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginMethodsWorkflow {

    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final RegisteredClientRepository registeredClientRepository;
    private final WalletLoginWorkflow walletLoginWorkflow;

    public record LoginMethods(List<String> methods, String essentialLevel) {
    }

    public sealed interface WalletRequestResult {

        record Created(String authRequest, long expiresIn) implements WalletRequestResult {
        }

        record LoginNotFound() implements WalletRequestResult {
        }

        record MethodNotOffered() implements WalletRequestResult {
        }
    }

    public Optional<LoginMethods> loginMethods(String state, String tenant) {
        return openLogin(state, tenant).map(login -> new LoginMethods(
                loginMethodsOf(login),
                Boolean.TRUE.equals(login.getAdditionalParameters().get(ACR_ESSENTIAL))
                        ? (String) login.getAdditionalParameters().get(ACR_REQUESTED)
                        : null));
    }

    public WalletRequestResult startWallet(String state, String tenant) {
        Optional<OAuth2AuthorizationRequest> open = openLogin(state, tenant);
        if (open.isEmpty()) {
            return new WalletRequestResult.LoginNotFound();
        }
        if (!loginMethodsOf(open.get()).contains(LoginMethod.WALLET.value())) {
            log.warn("event=login_wallet_not_offered clientId={}", sanitize(open.get().getClientId()));
            return new WalletRequestResult.MethodNotOffered();
        }
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(open.get().getClientId());
        if (registeredClient == null) {
            log.warn("event=login_wallet_client_not_found clientId={}", sanitize(open.get().getClientId()));
            return new WalletRequestResult.LoginNotFound();
        }

        OAuth2AuthorizationRequest login = cacheStoreForOAuth2AuthorizationRequest.compute(state,
                (key, current) -> current == null || current.getAdditionalParameters().containsKey(WALLET_AUTH_REQUEST)
                        ? current
                        : withWalletRequest(current, registeredClient, state));
        if (login == null || !(login.getAdditionalParameters().get(WALLET_AUTH_REQUEST) instanceof String authRequest)) {
            return new WalletRequestResult.LoginNotFound();
        }
        return new WalletRequestResult.Created(authRequest, secondsLeft(login));
    }

    private OAuth2AuthorizationRequest withWalletRequest(OAuth2AuthorizationRequest login,
                                                         RegisteredClient registeredClient, String state) {
        WalletLoginWorkflow.WalletLogin walletLogin = walletLoginWorkflow.start(registeredClient,
                String.join(" ", login.getScopes()), state, (String) login.getAdditionalParameters().get(ACCESS_PROFILE));
        log.info("event=login_wallet_request_created clientId={}", sanitize(login.getClientId()));
        return OAuth2AuthorizationRequest.from(login)
                .additionalParameters(walletLogin::addTo)
                .build();
    }

    private Optional<OAuth2AuthorizationRequest> openLogin(String state, String tenant) {
        OAuth2AuthorizationRequest login = cacheStoreForOAuth2AuthorizationRequest.getIfPresent(state);
        if (login == null) {
            log.debug("event=login_not_found state={}", sanitize(state));
            return Optional.empty();
        }
        Map<String, Object> parameters = login.getAdditionalParameters();
        if (!Objects.equals(parameters.get(AUTHORIZE_TENANT), tenant)) {
            log.warn("event=login_tenant_mismatch clientId={}", sanitize(login.getClientId()));
            return Optional.empty();
        }
        if (secondsLeft(login) <= 0) {
            log.debug("event=login_expired clientId={}", sanitize(login.getClientId()));
            return Optional.empty();
        }
        return Optional.of(login);
    }

    @SuppressWarnings("unchecked")
    private static List<String> loginMethodsOf(OAuth2AuthorizationRequest login) {
        Object methods = login.getAdditionalParameters().get(LOGIN_METHODS);
        return methods instanceof List<?> list ? (List<String>) list : List.of(LoginMethod.WALLET.value());
    }

    private static long secondsLeft(OAuth2AuthorizationRequest login) {
        if (!(login.getAdditionalParameters().get(EXPIRATION) instanceof Number expiration)) {
            return 0;
        }
        return Math.max(0, expiration.longValue() - Instant.now().getEpochSecond());
    }
}
