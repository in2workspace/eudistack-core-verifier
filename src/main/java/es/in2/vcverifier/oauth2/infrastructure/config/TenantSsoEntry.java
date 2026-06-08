package es.in2.vcverifier.oauth2.infrastructure.config;


import com.fasterxml.jackson.annotation.JsonProperty;

public record TenantSsoEntry(
        String tenant,
        String rootDomain,

        @JsonProperty("sso.enabled")
        Boolean ssoEnabled
) {}
