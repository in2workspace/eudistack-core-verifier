# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Multi-tenant access token claim** — The Verifier injects a signed `tenant` claim in the JWT access token, sourced from the `tenant` field in each OIDC client registration (`clients.yaml`). This enables downstream services (e.g., the Issuer) to cryptographically verify the tenant origin of each request without relying on HTTP headers (EUDI-017 Phase A).
- **CI/CD pipelines** — GitHub Actions workflows: `build.yml` with JaCoCo coverage summary, `release.yml` with manual `workflow_dispatch` trigger, `snapshot.yml` for PR Docker images.

### Changed

- **Dynamic issuer URL resolution** — `AuthorizationServerConfig` and `BackendConfig` now resolve the Verifier's issuer URL dynamically from the request, enabling multi-tenant subdomain routing without per-tenant configuration.
- **Version freeze** — `build.gradle` version set to `3.0.0` per architect decision (no version upgrades until stable release).
- **Google Java Style enforcement** — Checkstyle configured with 25+ rules (Google base + project adaptations). All violations fixed.
- **Dockerfile rewrite** — Multi-stage build with `gradlew`, 3-layer cache, OCI labels, HEALTHCHECK, standard port 8080.
- **application.yaml cleanup** — Standardized port to 8080, unified management config, explicit env var placeholders for all properties, fixed DCQL `learcredential` profile (added missing machine credentials).

### Removed

- **Embedded config files** — Removed `local/clients.yaml`, `local/trusted-issuers.yaml`, and `schemas/*.json` from classpath. All config is now injected via Docker volumes.

### Fixed

- **Tenant claim hardening** — Tenant value sanitized before injection into tokens; sensitive client data removed from log output.
- **Test stability** — Adapted `BackendConfigTest`, `FrontendConfigTest` for dynamic URL resolution; mocked `RegisteredClientRepository` in `VerifierApplicationTests`.

### Security

- **Sensitive data logging** — Removed client secret and credential data from log output in `ClientLoaderConfig` and `JWTServiceImpl`.

---

## [3.0.0] — 2026-03-12

First release of the EUDIStack Verifier Core as an independent repository. The codebase was imported from `in2-eudistack-verifier-core-api` (v2.1.0) and significantly restructured.

### Added

#### Architecture

- **Hexagonal architecture** — Complete reorganization into 3 bounded contexts (`verifier/`, `oauth2/`, `shared/`) with ports & adapters pattern. Domain layer has zero framework dependencies.
- **Application workflows** — Extracted business logic from Spring Security filters into testable workflow classes: `AuthorizationRequestBuildWorkflow`, `VerifyPresentationWorkflow`, `TokenGenerationWorkflow`, `ClientCredentialsValidationWorkflow`.
- **ArchUnit enforcement** — 17 architecture rules validating hexagonal layer boundaries, bounded context isolation, naming conventions, and dependency constraints.

#### OID4VP Protocol

- **DCQL query support** — Digital Credentials Query Language for credential presentation per OID4VP 1.0, with configurable scope-to-DCQL profile mapping (`verifier.dcql.profiles` in `application.yaml`).
- **SD-JWT VC verification** — Full SD-JWT VC (RFC 9901) verification pipeline: compact parsing, issuer JWT signature verification (DID or x5c), disclosure digest validation (SHA-256), KB-JWT validation (`aud`, `nonce`, `sd_hash`, `iat`, `cnf.jwk`).
- **DCQL vp_token extraction** — Automatic detection of DCQL (JSON object keyed by credential query IDs) vs legacy (direct JWT string) VP token formats.
- **OID4VP 1.0 audience validation** — VP `aud` claim validated against Verifier's `client_id` per OID4VP 1.0 Final.
- **Embedded JWK support** — VP verification supports JWK embedded in JWT header alongside legacy DID resolution.

#### Credential Validation

- **Schema-driven validation** — JSON Schema 2020-12 validation via `JsonSchemaCredentialValidator` (networknt/json-schema-validator). Schemas resolved by `LocalSchemaResolver` from classpath or external directory.
- **Schema profile claims extraction** — `SchemaProfileClaimsExtractor` replaces hardcoded `LearCredentialClaimsExtractor`. Claims extracted dynamically via JSON path with coalesce for cross-version compatibility.
- **Schema profile registry** — `LocalSchemaProfileRegistry` indexes credential profiles with `token_claims_mapping` for dynamic token claim generation.
- **Schema naming convention** — Adopted `{type}.{format}.{version}` pattern (e.g., `LEARCredentialEmployee.jwt_vc_json.v3.json`) with SD-JWT VCT resolution.
- **Credential type mapper** — `CredentialMapperService` maps VCs to typed credential objects for validation pipeline.
- **Cryptographic binding validator** — `CryptographicBindingValidator` extracted as dedicated component for JWK Thumbprint (RFC 7638) and DID comparison.
- **Credential status verification (Strategy pattern)** — `CredentialStatusVerifier` SPI with `BitstringStatusListVerifier` (W3C) and `TokenStatusListVerifier` (IETF) implementations. Non-blocking on infrastructure failures.
- **Flat token claims** — Access and ID tokens emit flat `mandatee.*`, `mandator.*`, and `power.*` claims instead of nested VC JSON.

#### Configuration & Injection

- **External file injection** — Clients YAML, trusted issuers YAML, and JSON Schemas injectable via Docker volumes or Kubernetes ConfigMaps without image rebuild (`VERIFIER_BACKEND_LOCALFILES_CLIENTSPATH`, `TRUSTEDISSUERSPATH`, `SCHEMASDIR`).
- **SPI provider selection** — `@ConditionalOnProperty` pattern for client registry (local/remote) and trusted issuers (local/EBSI v4).
- **Detailed issuer model** — Support for both simple (`string`) and detailed (`{id, name}`) issuer representations in VCs.

#### Security

- **SSRF protection** — `SafeUrlValidator` blocks requests to private/loopback/link-local addresses in all outbound HTTP calls (status lists, trust framework, EBSI).
- **RFC 7807 error responses** — `ErrorResponseFactory` generates Problem Details (RFC 7807) for all API errors, replacing ad-hoc error formats.
- **HTTP redirect following disabled** — `HttpClientConfig` sets `NEVER` redirect policy to prevent open redirect attacks.
- **Specific exception handlers** — Dedicated exception handlers for verification errors with appropriate HTTP status codes and OID4VP error codes.
- **Dynamic CORS origins** — CORS origins for OIDC endpoints loaded dynamically from registered client URLs instead of static configuration.

#### Observability

- **OpenTelemetry tracing** — Spans for critical verification paths via Micrometer + OTel bridge.
- **Non-blocking revocation** — Status list fetch failures log `WARN` and continue validation instead of blocking the VP verification flow.
- **Endpoint log suppression** — `SuppressEndpointLogFilter` filters noisy health/actuator endpoints from access logs.
- **Structured logging** — `logback-spring.xml` with JSON structured logging for production.

#### Testing

- **434 tests** across 51 test files (~1.15:1 test-to-code ratio).
- New test coverage: `SseEmitterStore`, `UVarInt`, `DcqlProfileResolver`, `RemoteClientRegistryProvider`, `EbsiV4TrustedIssuersProvider`, `SchemaProfileClaimsExtractor`, `BitstringStatusListVerifier`, `TokenStatusListVerifier`, `SafeUrlValidator`, `ClientLoaderConfig`.

### Changed

- **Java 17 → 25** — Eclipse Temurin 25 runtime.
- **Gradle 8.8 → 9.3.1** — Updated build tool and wrapper.
- **Spring Boot 3.3.2 → 3.5.11** — Major framework upgrade.
- **ArchUnit 1.3.0 → 1.4.1** — Java 25 bytecode support.
- **OWASP dependency-check 9.1.0 → 12.2.0** — Updated vulnerability scanner.
- **SonarQube plugin 5.1.0 → 6.0.1**, Swagger 2.2.22 → 2.2.28.
- **OAuth2 filters slimmed down** — `CustomAuthorizationRequestConverter` (524 → ~280 lines), `CustomAuthenticationProvider` (392 → ~258 lines), `CustomTokenRequestConverter` (229 → ~154 lines). All delegate to application workflows.
- **Ubiquitous language naming** — Methods and services renamed to match protocol verbs (`verifyPresentation`, `resolveClientId`, `extractCredentialClaims`, etc.).
- **Checkstyle config path** — Moved from `checkstyle/` to `config/checkstyle/` (Gradle convention).
- **Dockerfile** — `gradle:9.1.0-jdk25` build stage + `eclipse-temurin:25-jre-alpine` runtime.

### Removed

- **Hardcoded claims extractor** — `LearCredentialClaimsExtractor` replaced by schema-driven `SchemaProfileClaimsExtractor`.
- **`presentation_submission` parameter** — Removed from auth response endpoint (DCQL replaces it).
- **Shared Claude context submodule** — `.claude/` config and `.gitmodules` removed.

### Security Fixes (from internal audit)

| ID | Issue | Fix |
|----|-------|-----|
| P0-1 | HttpClient instantiated per request | `HttpClientConfig` singleton (connect 10s, read 30s) |
| P0-2 | `assert` in grantType validation | Explicit validation with proper exception |
| P0-3 | No HTTP timeouts | Global timeouts via `HttpClientConfig` |
| P0-4 | VP `aud` validation commented out | Re-enabled in `AuthorizationResponseProcessorServiceImpl` |
| P0-5 | FAPI nonce disabled | `IS_NONCE_REQUIRED = true` |
| P0-6 | `@Scheduled` + `@Bean` combined | Separated in `ClientLoaderConfig` |

---

## Legacy Releases (from in2-eudistack-verifier-core-api)

> The following releases were made in the original repository [`in2workspace/in2-verifier-api`](https://github.com/in2workspace/in2-verifier-api). They are preserved here for historical reference.

## [2.1.0] — 2026-02-27

Internal refactoring release. Hexagonal architecture, workflow extraction, external file injection, SSE login, and external frontend support. See v3.0.0 above — this version was the basis for the new repository.

## [2.0.12]

### Fixed

- Bitstring-encoded status lists read using MSB-first ordering.

## [2.0.11]

### Added

- Support for `BitstringStatusListEntry` credential status type.

## [2.0.10]

### Added

- Cryptographic binding verification for VP/VC holder key matching.

## [2.0.9] – [2.0.3]

### Changed

- UI/branding changes to the embedded Thymeleaf login page (removed in v3.0.0): logo responsiveness, color variables, dynamic logo/favicon URLs, favicon updates, text fixes, hardcoded "DOME" references removed, Accept-Language header support, configurable default language.

## [2.0.2]

### Added

- Configurable default language for HTML template translation.

## [2.0.1]

### Added

- Authorization Code Flow with PKCE for Relying Party authentication.

## [2.0.0]

Major version bump to align with the EUDIStack platform version.

## [1.3.11]

### Added

- Revocation check for credentials with `credentialStatus` field.

## [1.3.10] – [1.3.9]

### Added

- Prometheus metrics endpoint access through Spring Security.

## [1.3.8]

### Added

- Audience and nonce validation for OID4VP authorization responses.
- Specific OID4VP exceptions for validation failures.
- `type` claim handling in Authorization Request.

## [1.3.7]

### Fixed

- Token response scoped correctly per grant type (`client_credentials` excludes `id_token`/`refresh_token`).
- Scopes `profile` and `email` always included in `id_token`.
- `client_id_scheme` set to `did:key` in authorization request.
- `client_id` in access token returns URL.

### Added

- `LEARCredentialMachine` support.
- DID Key extracted as environment variable.

## [1.3.6]

### Fixed

- Backward compatibility for `LEARCredentialEmployee` v2.0 with v1.0 claims.

## [1.3.5]

### Fixed

- M2M `vp_token` validation issue.

## [1.3.4]

### Fixed

- Login flow error when QR login timeout expires.

## [1.3.3]

### Fixed

- Issuer field serialization issue.

## [1.3.2]

### Fixed

- Access token timeout configuration.

## [1.3.1]

### Fixed

- `@JsonProperty` annotation on `LEARCredential` record.

## [1.3.0]

### Added

- `LEARCredentialEmployee` v2.0 support.

## [1.2.1]

### Changed

- Updated DOME logo.

## [1.2.0]

### Changed

- Redesigned login page UI.
- Refactored configuration: removed unused parameters, grouped into `frontend`/`backend` categories.

## [1.1.0]

### Added

- Refresh token support for OIDC flow.
- Nonce support for authorization code flow.

## [1.0.17]

### Added

- Documentation for OIDC client registration and verifier interaction.

## [1.0.16]

### Fixed

- Time window validation (`validFrom`/`validUntil`) for credentials in Verifiable Presentations.

## [1.0.15]

### Fixed

- Token serialization issue.
- CORS configuration for registered clients.

## [1.0.14]

### Fixed

- Renamed `verifiableCredential` claim to `vc` in access token.

## [1.0.13]

### Fixed

- "Contact us" link not working on login page.

## [1.0.12]

### Fixed

- Return 401 Unauthorized (not 500) for VP token validation failures.

## [1.0.11]

### Fixed

- CORS configuration to allow requests from external wallets on OID4VP endpoints.

## [1.0.10]

### Added

- Error page for client authentication request failures.

## [1.0.9]

### Fixed

- Image URL resolution.
- Tablet layout spacing between navbar and content.

## [1.0.8]

### Fixed

- Color contrast accessibility.
- Brand colors, font, and favicon.
- Layout responsiveness.

## [1.0.7]

### Fixed

- JWKS endpoint response: added `use: "sig"` claim.

## [1.0.6]

### Fixed

- Authentication request compliance with OpenID Connect Core standard.

## [1.0.5]

### Fixed

- Token response compliance with OpenID Connect Core standard.

## [1.0.4]

### Fixed

- Security issue with signature verification.

## [1.0.3]

### Added

- **OpenID Connect support** — Authorization Code Flow (without PKCE), scope-based claims (`openid learcredential`), Request Object by Reference (JAR), Private Key JWT client authentication, ES256 access token signing.
- **OpenID for Verifiable Presentations (OID4VP)** — VP Proof of Possession verification, issuer/participant/service verification against DOME Trust Framework, VC revocation check against DOME Revoked Credentials List.
- **FAPI profile** — `request_uri` as required claim in Authentication Request Object.
- **DOME H2M authentication** — Login page with QR code for wallet interaction.
- **DOME M2M authentication** — `client_credentials` grant with client assertion JWT.
- **DOME Trust Framework integration**.

### Fixed

- Login page: wallet URL display, registration URL validation, QR code expiration redirect.
