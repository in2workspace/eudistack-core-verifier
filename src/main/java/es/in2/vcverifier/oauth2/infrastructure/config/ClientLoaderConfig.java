package es.in2.vcverifier.oauth2.infrastructure.config;

import es.in2.vcverifier.oauth2.domain.exception.ClientLoadingException;
import es.in2.vcverifier.oauth2.infrastructure.adapter.DelegatingRegisteredClientRepository;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_TENANT;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ClientLoaderConfig {

    private static final Pattern TENANT_PATTERN = Pattern.compile("^[a-z0-9-]{1,64}$");

    private final ClientRegistryProvider clientRegistryProvider;
    private final Set<String> allowedClientsOrigins;

    private final AtomicReference<RegisteredClientRepository> repositoryRef = new AtomicReference<>();

    @Bean
    public RegisteredClientRepository getRegisteredClientRepository() {
        RegisteredClientRepository initialRepo = buildRepository();
        repositoryRef.set(initialRepo);
        return new DelegatingRegisteredClientRepository(repositoryRef);
    }

    @Scheduled(cron = "0 */30 * * * *")
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
                registeredClientBuilder.clientSettings(clientSettingsBuilder.build());
                registeredClients.add(registeredClientBuilder.build());

                if (clientData.url() != null && !clientData.url().isBlank()) {
                    freshOrigins.add(clientData.url());
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
}
