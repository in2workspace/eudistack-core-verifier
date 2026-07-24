package es.in2.vcverifier.oauth2.infrastructure.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.oauth2.domain.exception.SsoConfigLoadingException;
import es.in2.vcverifier.shared.config.properties.BackendProperties;
import es.in2.vcverifier.shared.domain.model.EligibleClientConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.locks.ReentrantLock;

@Slf4j
@Component
public class TenantSsoConfigYamlProvider implements TenantSsoConfigProvider {

    private final BackendProperties backendProperties;
    private final ObjectMapper yamlMapper;
    private final ReentrantLock writeLock = new ReentrantLock();

    public TenantSsoConfigYamlProvider(BackendProperties backendProperties) {
        this.backendProperties = backendProperties;
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
        log.info("SSO config path = {}", backendProperties.localFiles() != null
                ? backendProperties.localFiles().ssoConfigPath()
                : "NULL");
    }

    @Override
    public TenantSsoConfigYamlData retrieve() {

        try {
            String path = backendProperties.localFiles() != null
                    ? backendProperties.localFiles().ssoConfigPath()
                    : null;

            if (path != null && !path.isBlank()) {
                try (InputStream is = Files.newInputStream(Path.of(path))) {
                    return parseAndNormalize(is);
                } catch (java.nio.file.NoSuchFileException e) {
                    log.warn("sso-config.yaml not found at path: {}. Falling back to classpath.", path);
                }
            }

            InputStream is = getClass().getClassLoader().getResourceAsStream("sso-config.yaml");
            if (is == null) {
                log.warn("sso-config.yaml not found in classpath. Returning empty SSO config.");
                return new TenantSsoConfigYamlData(List.of());
            }

            try (is) {
                return parseAndNormalize(is);
            }

        } catch (Exception e) {
            log.error("Error loading SSO config", e);
            throw new SsoConfigLoadingException("Error loading SSO config", e);
        }
    }

    // =========================================================
    // WRITE PATH — AD-1: el catálogo vive en la config YAML/EFS
    // =========================================================

    @Override
    public boolean addEligibleClient(String tenant, String clientId) {
        return modifyEligibleClients(tenant, clientId, true);
    }

    @Override
    public boolean removeEligibleClient(String tenant, String clientId) {
        return modifyEligibleClients(tenant, clientId, false);
    }

    /**
     * Modifica la lista eligibleClients del tenant en el fichero YAML externo.
     * Requiere que {@code verifier.backend.local-files.sso-config-path} esté configurado.
     * Escritura atómica (fichero temporal + rename) para proteger lecturas concurrentes.
     * Lock intra-JVM para serializar escrituras en el mismo proceso.
     * [F3]: normaliza el tenant a lowercase antes de comparar para evitar no-ops silenciosos.
     */
    private boolean modifyEligibleClients(String tenant, String clientId, boolean add) {
        String configPath = resolveWritablePath();
        String normalizedTenant = tenant != null ? tenant.toLowerCase(Locale.ROOT) : null;
        writeLock.lock();
        try {
            Path file = Path.of(configPath);

            TenantSsoConfigYamlData current;
            try (InputStream is = Files.newInputStream(file)) {
                current = yamlMapper.readValue(is, TenantSsoConfigYamlData.class);
            }

            boolean tenantFound = false;
            boolean changed = false;
            List<TenantSsoEntry> updatedTenants = new ArrayList<>(current.tenants().size());
            for (TenantSsoEntry entry : current.tenants()) {
                String entryTenant = entry.tenant() != null
                        ? entry.tenant().toLowerCase(Locale.ROOT) : null;
                if (!normalizedTenant.equals(entryTenant)) {
                    updatedTenants.add(entry);
                    continue;
                }
                tenantFound = true;
                List<EligibleClientConfig> clients = new ArrayList<>(entry.eligibleClients());
                if (add) {
                    boolean exists = clients.stream().anyMatch(c -> c.clientId().equals(clientId));
                    if (!exists) {
                        clients.add(EligibleClientConfig.of(clientId));
                        changed = true;
                    }
                } else {
                    changed = clients.removeIf(c -> c.clientId().equals(clientId));
                }
                updatedTenants.add(new TenantSsoEntry(
                        entry.tenant(), entry.rootDomain(), entry.ssoEnabled(),
                        List.copyOf(clients), entry.ttlAbsolute(), entry.ttlIdle()
                ));
            }

            if (!tenantFound) {
                log.warn("event=sso_catalog_tenant_not_found tenant={} operation={}",
                        tenant, add ? "ADD" : "REMOVE");
                return false;
            }
            if (!changed) return false;

            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            yamlMapper.writeValue(tmp.toFile(), new TenantSsoConfigYamlData(updatedTenants));
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);

            log.info("event=sso_catalog_yaml_updated tenant={} clientId={} operation={}",
                    tenant, clientId, add ? "ADD" : "REMOVE");
            return true;

        } catch (IOException e) {
            throw new SsoConfigLoadingException("Failed to update SSO catalog in config file", e);
        } finally {
            writeLock.unlock();
        }
    }

    private String resolveWritablePath() {
        String path = backendProperties.localFiles() != null
                ? backendProperties.localFiles().ssoConfigPath()
                : null;
        if (path == null || path.isBlank()) {
            throw new SsoConfigLoadingException(
                    "Cannot modify SSO catalog: external sso-config.yaml not configured "
                    + "(verifier.backend.local-files.sso-config-path is required for catalog admin operations)");
        }
        return path;
    }

    private TenantSsoConfigYamlData parseAndNormalize(InputStream is) throws Exception {
        TenantSsoConfigYamlData data = yamlMapper.readValue(is, TenantSsoConfigYamlData.class);

        List<TenantSsoEntry> tenants = data.tenants() != null ? data.tenants() : List.of();

        List<TenantSsoEntry> normalized = tenants.stream()
                .map(e -> e.eligibleClients() != null
                        ? e
                        : new TenantSsoEntry(e.tenant(), e.rootDomain(), e.ssoEnabled(),
                                List.of(), e.ttlAbsolute(), e.ttlIdle()))
                .toList();

        log.info("ALL TENANTS LOADED = {}", normalized.stream().map(TenantSsoEntry::tenant).toList());

        return new TenantSsoConfigYamlData(normalized);
    }
}
