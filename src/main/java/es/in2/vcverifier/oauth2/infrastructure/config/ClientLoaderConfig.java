package es.in2.vcverifier.oauth2.infrastructure.config;

import es.in2.vcverifier.oauth2.domain.exception.ClientLoadingException;
import es.in2.vcverifier.oauth2.infrastructure.adapter.DelegatingRegisteredClientRepository;
import es.in2.vcverifier.shared.domain.util.OriginNormalizer;
import es.in2.vcverifier.verifier.domain.model.ClientData;
import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_LOGIN_PAGE_URI;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_TENANT;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_CLIENT_METADATA;
import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_BACKCHANNEL_LOGOUT_URI;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ClientLoaderConfig {

    private static final Pattern TENANT_PATTERN = Pattern.compile("^[a-z0-9-]{1,64}$");
    private static final String HTTPS_SCHEME = "https";
    private static final String HTTP_SCHEME = "http";

    private final ClientRegistryProvider clientRegistryProvider;
    private final Set<String> allowedClientsOrigins;

    private final AtomicReference<RegisteredClientRepository> repositoryRef = new AtomicReference<>();

    @Bean
    public RegisteredClientRepository getRegisteredClientRepository() {
        RegisteredClientRepository initialRepo = buildRepository();
        repositoryRef.set(initialRepo);
        return new DelegatingRegisteredClientRepository(repositoryRef);
    }

    @Scheduled(cron = "${verifier.oauth2.clientRefreshCron:0 */5 * * * ?}")
    public void refreshClients() {
        try {
            log.info("Refreshing client registry...");
            RegisteredClientRepository refreshedRepo = buildRepository();
            repositoryRef.set(refreshedRepo);
            log.info("Client registry refreshed successfully");
        } catch (Exception e) {
            log.error("Failed to refresh client registry, keeping previous version", e);
        }
    }

    private RegisteredClientRepository buildRepository() {
        List<RegisteredClient> clients = retrieveClients();
        return new InMemoryRegisteredClientRepository(clients);
    }

    private List<RegisteredClient> retrieveClients() {
        try {
            ExternalTrustedListYamlData clientsYamlData = clientRegistryProvider.retrieveClients();
            List<RegisteredClient> registeredClients = new ArrayList<>();
            Set<String> freshOrigins = new java.util.HashSet<>();
            for (ClientData clientData : clientsYamlData.clients()) {
                RegisteredClient.Builder registeredClientBuilder = RegisteredClient
                        .withId(UUID.randomUUID().toString())
                        .clientId(clientData.clientId())
                        .clientAuthenticationMethods(authMethods -> clientData.clientAuthenticationMethods().forEach(method -> authMethods.add(new ClientAuthenticationMethod(method))))
                        .authorizationGrantTypes(grantTypes -> clientData.authorizationGrantTypes().forEach(grantType -> grantTypes.add(new AuthorizationGrantType(grantType))))
                        .redirectUris(uris -> uris.addAll(clientData.redirectUris()))
                        .postLogoutRedirectUris(uris -> uris.addAll(clientData.postLogoutRedirectUris()))
                        .scopes(scopes -> scopes.addAll(clientData.scopes()))
                        .clientName(clientData.url());

                if (clientData.clientSecret() != null && !clientData.clientSecret().isBlank()) {
                    log.warn("Client '{}' has a plaintext secret in config. Use a secrets manager for production.", clientData.clientId());
                    registeredClientBuilder.clientSecret(clientData.clientSecret());
                }
                ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder().requireAuthorizationConsent(clientData.requireAuthorizationConsent());
                if (clientData.jwkSetUrl() != null) {
                    clientSettingsBuilder.jwkSetUrl(clientData.jwkSetUrl());
                }
                if (clientData.tokenEndpointAuthenticationSigningAlgorithm() != null) {
                    clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.from(clientData.tokenEndpointAuthenticationSigningAlgorithm()));
                }
                if (clientData.requireProofKey() != null) {
                    clientSettingsBuilder.requireProofKey(clientData.requireProofKey());
                }
                if (clientData.tenant() != null && !clientData.tenant().isBlank()) {
                    if (!TENANT_PATTERN.matcher(clientData.tenant()).matches()) {
                        throw new ClientLoadingException("Invalid tenant identifier '" + clientData.tenant()
                                + "' for client '" + clientData.clientId() + "'. Must match: " + TENANT_PATTERN.pattern());
                    }
                    clientSettingsBuilder.setting(CLIENT_SETTING_TENANT, clientData.tenant());
                }
                if (clientData.clientMetadata() != null) {
                    clientSettingsBuilder.setting(CLIENT_SETTING_CLIENT_METADATA, clientData.clientMetadata());
                }
                if (clientData.backchannelLogoutUri() != null && !clientData.backchannelLogoutUri().isBlank()) {
                    // [B3] SEC-14: mismo enforcement HTTPS que loginPageUri — el host/rango
                    // privado se valida en resolución (RegisteredClientBackchannelLogoutUriResolver,
                    // vía SafeUrlValidator), pero el esquema se rechaza ya en el registro.
                    URI backchannelLogoutUri = URI.create(clientData.backchannelLogoutUri());
                    if (!HTTPS_SCHEME.equalsIgnoreCase(backchannelLogoutUri.getScheme())) {
                        throw new ClientLoadingException("backchannelLogoutUri must use HTTPS scheme for client '"
                                + clientData.clientId() + "': " + clientData.backchannelLogoutUri());
                    }
                    clientSettingsBuilder.setting(CLIENT_SETTING_BACKCHANNEL_LOGOUT_URI, clientData.backchannelLogoutUri());
                }
                if (clientData.loginPageUri() != null && !clientData.loginPageUri().isBlank()) {
                    URI loginUri = URI.create(clientData.loginPageUri());
                    if (!HTTPS_SCHEME.equalsIgnoreCase(loginUri.getScheme())) {
                        throw new ClientLoadingException("loginPageUri must use HTTPS scheme for client '"
                                + clientData.clientId() + "': " + clientData.loginPageUri());
                    }
                    clientSettingsBuilder.setting(CLIENT_SETTING_LOGIN_PAGE_URI, clientData.loginPageUri());
                    addNormalizedOrigin(freshOrigins, loginUri);
                }
                registeredClientBuilder.clientSettings(clientSettingsBuilder.build());
                registeredClients.add(registeredClientBuilder.build());

                if (clientData.url() != null && !clientData.url().isBlank()) {
                    addNormalizedOrigin(freshOrigins, clientData.url());
                }
                if (clientData.redirectUris() != null) {
                    for (String redirectUri : clientData.redirectUris()) {
                        URI redirectUriParsed = URI.create(redirectUri);
                        String scheme = redirectUriParsed.getScheme();
                        if (HTTP_SCHEME.equalsIgnoreCase(scheme) || HTTPS_SCHEME.equalsIgnoreCase(scheme)) {
                            addNormalizedOrigin(freshOrigins, redirectUriParsed);
                        }
                    }
                }
            }
            // Atomically replace origins: remove stale, add fresh
            allowedClientsOrigins.retainAll(freshOrigins);
            allowedClientsOrigins.addAll(freshOrigins);
            return registeredClients;
        } catch (Exception e) {
            throw new ClientLoadingException("Error loading clients from Yaml", e);
        }
    }

    private void addNormalizedOrigin(Set<String> origins, String uri) {
        addOrigin(origins, OriginNormalizer.normalize(uri));
    }

    private void addNormalizedOrigin(Set<String> origins, URI uri) {
        addOrigin(origins, OriginNormalizer.normalize(uri));
    }

    private void addOrigin(Set<String> origins, URI normalizedOrigin) {
        if (normalizedOrigin != null) {
            origins.add(normalizedOrigin.toString());
        }
    }
}
