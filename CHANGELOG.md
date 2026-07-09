****# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added 2026-07-06

- **US-08 — Legacy application coexistence on the Verifier IdP (EUDISTACK-553)**: 0 regressions for non-migrated tenants/applications during the transition to SSO (FR-14, NFR-M-01). Legacy tenant (`sso.enabled=false` or no `tenant_sso` entry) → fail-closed without creating a session or cookie; `prompt=none` on a legacy tenant → `error=login_required` to the `redirect_uri` (no QR render, residual SSO cookie ignored, no `code`/`id_token`). Coexistence verification suite: `EstablishSsoSessionWorkflow_SsoDisabledTest`/`_ConfigAbsentTest` (guard unit tests), `LegacyConvivenciaIT` (SSO+legacy coexistence and flag flip) and `PromptNoneLegacyIT` (AC-03/ES-02). ACs covered: AC-01..AC-03, EC-01..EC-02, ES-01..ES-02, NFR-S-553-01, NFR-S-553-02.

### Changed - 2026-07-08

- **`sso-config.yaml`: example `rootDomain` values replaced with real domains**: the placeholder values (`*.example.com`) for tenants `sandbox`, `cgcom`, `kpmg`, `dome` and `platform` are replaced with the real root domains (`*.stg.eudistack.net` and, for `dome`, `dome-marketplace-lcl.org`) used by the per-tenant SSO catalog (EUDISTACK-550 US-05).

### Added
- **EUDISTACK-546**: 
- US-01: Custom domain operativo per tenant en el Verifier IdP
- US-02: Sesión SSO establecida tras presentación OID4VP exitosa
- US-03: Reutilización silenciosa de la sesión SSO en aplicativos adicionales
- **US-05 — Catálogo per tenant de aplicativos elegibles para SSO (EUDISTACK-550)**: Catálogo de clientes elegibles para reutilización silenciosa de sesión SSO por tenant (FR-09, FR-10, FR-14). Nuevos componentes de dominio: `SsoEligibleClient` (value object con normalización trim canónica, EC-04), `TenantSsoCatalog` (value object agrupador con fail-closed AC-03: `contains()` devuelve false si el catálogo está vacío o el clientId no figura). Política AD-2: `TenantSsoPolicy.evaluate(6 params)` evalúa tres condiciones AND en orden estricto — (1) cliente registrado en el servidor OAuth (REJECT_SESSION si falla), (2) sesión vigente según TTL absoluto (REJECT_SESSION si falla), (3) cliente en el catálogo SSO del tenant (REJECT_CATALOG → interaction_required si falla). API de administración: `TenantSsoCatalogAdminController` con endpoints `GET/POST/DELETE /tenant/sso/eligible-clients` protegidos por sesión autenticada (AD-3); validación cross-tenant ES-03 (401 si no hay contexto de tenant, 403 si el tenant de la sesión autenticada difiere del tenant de la solicitud). Persistencia AD-1: alta/baja escriben sobre el fichero YAML/EFS (`TenantSsoConfigYamlAdapter` implementa `SsoCatalogRepositoryPort`) y refrescan el caché en memoria; la decisión de reuse lee del mismo caché. Auditoría NFR-O-01: `SSO_CATALOG_CLIENT_ADDED`/`SSO_CATALOG_CLIENT_REMOVED` emitidos en cada operación. ACs cubiertos: AC-01..AC-05, EC-01..EC-04, ES-01..ES-03, NFR-S-550-01, NFR-P-550-01.
- **US-04 — TTL de sesión SSO configurable per tenant (EUDISTACK-549)**: TTL de sesión SSO configurable por dimensión per tenant (FR-07) con valor por defecto de sistema (FR-08, default ADR-106: 8h absoluto / 30min idle). Nuevos componentes de dominio: `SsoTtlRange` (constantes canónicas ADR-106 — rango absoluto [1h, 24h], idle [5min, 60min], defaults 8h/30min), `SsoSessionTtl` (value object inmutable que encapsula el par absolute+idle validado en construcción), `TenantSsoTtlPolicy` (servicio de dominio con `validate(absolute, idle)` — rangos cerrados inclusivos, log estructurado de rechazo por dimensión — y `resolve(overrideAbsolute, overrideIdle)` — override por dimensión independiente con cap idle≤absolute). Extensiones: `SsoSession.isValid(now, idleTtl)` (criterio combinado `now < expiresAt AND now − lastUsedAt ≤ idleTtl`), `TenantSsoConfigPort.resolveTtl(tenant)`, `TenantSsoConfigYamlAdapter` (parseo de campos `ttlAbsolute`/`ttlIdle` en YAML per tenant, fail-safe a última config válida ante fallo de lectura ES-02, aislamiento per-tenant de valores mal formados ES-01), `EstablishSsoSessionWorkflow` (fija `expiresAt` desde TTL resuelto) y `ReuseSsoSessionWorkflowImpl` (evalúa `isValid` con TTL idle vigente en config). ACs cubiertos: AC-01..AC-05, EC-01..EC-03, ES-01..ES-02, NFR-S-549-01, NFR-P-549-01.

### Changed - 2026-07-06

- **Redirect/CORS origin allowlisting hardened (SEC-S7 follow-up)**: `CustomErrorResponseHandler.isAllowedRedirectUri` ya no confía en el origen del propio verifier derivado dinámicamente de `BackendConfig.getUrl()` (que a su vez resolvía el Host de la request vía `ForwardedHeaderFilter`). Nuevo campo `verifier.backend.additional-urls` (`BackendProperties.additionalUrls`, opcional, `List<String>`) modela explícitamente los dominios alias del verifier (SSO multi-tenant/multi-app), separado de `verifier.backend.url` (que sigue siendo el `String` canónico usado como `iss`/audiencia/`response_uri` — sin ambigüedad de "cuál es el principal"). `BackendConfig.getAllUrls()` devuelve `url` seguido de `additionalUrls`; el nuevo `BackendConfig.getTrustedVerifierOrigins()` normaliza ese conjunto completo como orígenes confiables para los redirects propios del verifier — estático y configurable, sin depender de qué Host reenvíe el proxy. Nueva utilidad `OriginNormalizer` normaliza scheme/host (minúsculas, puerto por defecto omitido, comparación de scheme case-insensitive) en las tres comparaciones de origen existentes (`ClientLoaderConfig`, `CustomErrorResponseHandler`, y el matching de `redirect_uri` en `CustomAuthorizationRequestConverter.validateRedirectUri`), evitando rechazos por diferencias puramente sintácticas (RFC 3986 §3.1/§3.2.2) sin relajar la comparación exacta de path/query en `redirect_uri`.

### Fixed - 2026-07-06

- **`CustomErrorResponseHandlerTest` desalineado tras merge de `main`**: el stub `backendConfig.getStaticUrl()` no se correspondía con el método realmente invocado por `CustomErrorResponseHandler.isAllowedRedirectUri()` (`backendConfig.getUrl()`), causando `WantedButNotInvoked` en `testOnAuthenticationFailure_WithVerifierOwnOrigin_ShouldRedirect` y `testOnAuthenticationFailure_WithVerifierOwnOriginErrorPage_ShouldRedirect`. Corregido el stub para apuntar a `getUrl()`.
- **`CryptographicBindingValidatorTest` con stub incompleto**: `validateCryptographicBinding_allStrategiesMiss_throwsInvalidScopeException` no stubaba `getClaim("vc")`, dependiendo de que el `catch` interno de `extractMandateeIdFromVc` absorbiera el `PotentialStubbingProblem` de Mockito. Añadido el stub explícito para eliminar la fragilidad del test.

### Added - 2026-06-22

- **DOME legacy `PlainListEntity` revocation skip**: `VpServiceImpl.validateCredentialNotRevoked` short-circuits to `not revoked` (WARN log) when `credentialStatus.type == "PlainListEntity"`. Resolves the previous `Unsupported credentialStatus.type` exception that broke OID4VP login for DOME legacy credentials, whose revocation lists are plain JSON arrays of `{ "nonce": "<id>" }` (no JWT, no signature) and not exposed by any existing `CredentialStatusVerifier` strategy. Intentional during the DOME legacy sunset window; inline `TODO` captures the open decision (migrate legacy to `BitstringStatusListEntry` vs implement a real `PlainListEntityVerifier` adapter).

### Changed - 2026-06-18
- Upgraded `org.bouncycastle:bcprov-jdk18on` from `1.80` to `1.84`. 
- Upgraded `org.bouncycastle:bcpkix-jdk18on` from `1.80` to `1.84`.
- Removed explicit version pin from `jackson-dataformat-yaml` to use the Spring Boot managed BOM version.

### Fixed - 2026-06-22

- **SD-JWT credential types missing from dispatch catalogue**: `learcredential.employee.sd.1`, `learcredential.machine.sd.1` and `doctorid.sd.1` were absent from the `verifier.dispatch.rules` introduced in eba0126 (PR #31). Any wallet presenting an SD-JWT VC received `UnknownCredentialFormatException → HTTP 400` after full JWT + KB-JWT + status-list verification had already passed. Added the three SD-JWT config IDs to the `bumped` rule set. `FlagDefaultsTest` updated to assert the new catalogue sizes (6 legacy / 6 bumped / 12 total) and verify the SD-JWT entries explicitly.

### Added - 2026-06-17

- **Dual-format dispatcher (US-08 / EUDISTACK-145)**: new `CredentialSchemaDispatcher` port + `ContextAndTypeCredentialSchemaDispatcher` adapter that classifies every incoming credential as `LEGACY_V1_1` or `BUMPED_V2_0` from `type[]` + `@context`, deterministically and without try/catch fallback (AD-3). The decision drives a `LegacyCredentialReader` / `BumpedCredentialReader` SPI and an `AccessTokenBuilder` (`JwsAccessTokenBuilder`) that wraps the credential under `vc` only for VCDM v2.0 — preserving the legacy wrap for v1.1 (FR-06a). Domain ports: `CredentialReader`, `AccessTokenBuilder`, `CredentialSchemaDispatcher`, `TenantConfigPort`. Records: `DispatchDecision`, `DispatchRule`, `DispatchReason`, `CredentialFormat`, `BuildContext`, `ReaderResult`, `TenantDomeConfig`.
- **Independent feature flags `verifier.dome.legacy-read-enabled` and `verifier.dome.bumped-read-enabled`** (`TenantDomeConfigProperties` + `PropertiesTenantConfigAdapter`): boolean toggles (default `true`) that gate legacy and bumped credential acceptance per tenant. Closing the legacy flag triggers `LegacyFormatSunsetClosedException → 410 Gone`; disabling the bumped flag triggers `BumpedFormatTemporarilyDisabledException → 503 Service Unavailable`. Source is currently `@ConfigurationProperties`; the spec target (DB-backed `tenant_dome_config` with TTL ≤ 60 s hot-reload, AC-07 / NFR-S-145-03) is documented as follow-up.
- **Dispatcher catalogue in `application.yaml`** (`verifier.dispatch.rules.legacy/bumped`): `DispatchProperties` + `DispatchConfiguration` register a `List<DispatchRule>` of `credential-configuration-id → CredentialFormat` from configuration so adding new DOME or EUDIStack types is config-only, no recompile. Default catalogue covers `learcredential.{employee,machine}.w3c.{2,3,4}` and `gx.labelcredential.w3c.{1,2}` plus the raw DOME type aliases `LEARCredentialEmployee` and `LEARCredentialMachine`.
- **RFC 9457 Problem+JSON error mapping** (`DomeDispatchExceptionHandler`): three new exceptions (`LegacyFormatSunsetClosedException`, `BumpedFormatTemporarilyDisabledException`, `UnknownCredentialFormatException`) mapped to `410` / `503` / `400` with a stable `properties.error` code (`legacy_format_sunset_closed`, `bumped_format_temporarily_disabled`, `unknown_credential_format`) so callers can branch on the machine-readable identifier instead of the human-readable `detail`.
- **Micrometer instrumentation**: counter `dome_verifier_dispatcher_total{tenant, format, decision, reason}` and timer `dome_verifier_dispatcher_duration_ms{tenant}` in the dispatcher; counter `dome_verifier_legacy_replay_after_sunset_total{tenant}` in the exception handler. Drives the cutover dashboard / sunset-closure alerting (`architecture.md` §9.3).

### Changed - 2026-06-17

- **`AuthorizationResponseProcessorServiceImpl.handleAuthResponse`**: after JWT VP validation, the workflow now invokes `CredentialSchemaDispatcher.dispatch(credential)` so the OID4VP user-driven login path is subject to the same format gating as the M2M `client_credentials` grant (US-08 AC-07 / AC-10). The three dispatcher exceptions are added to the outer catch tree and trigger an SSE `FORMAT_GATED` event so the wallet can surface a specific message.
- **`VerifyPresentationWorkflow`**: returns a `(credential, dispatchDecision)` record after dispatch so downstream workflows can read the resolved format and config-id without re-classifying.
- **`TokenGenerationWorkflow`**: access-token construction delegated to the new `AccessTokenBuilder` port. The legacy/bumped distinction is honoured by the builder via `SchemaProfile.wrapVcInAccessToken`: VCDM v1.1 credentials pass through unmodified (their JWT already carries the `vc` wrap); VCDM v2.0 credentials are wrapped under `vc` exclusively at the verifier (FR-06a, FR-06b: issuers must not pre-wrap). `id_token` construction stays inside the workflow.
- **`ClientCredentialsValidationWorkflow`**: invokes the dispatcher to enrich logs/metrics on M2M flows and gate access at the same point as OID4VP. `grantEligibility` lookup against `SchemaProfileRegistry` unchanged.
- **`SchemaProfile`**: new boolean field `wrapVcInAccessToken` (default `false`, expected `true` for bumped profiles loaded from `eudistack-platform-assets`). Decouples format detection from access-token construction.
- **`LocalSchemaProfileRegistry`**: now scans the `legacy/` subdirectory under the external schemas path, registers `type → profile` aliases via `registerCredentialTypeAliases` so credentials carrying bare semantic types in `type[]` (e.g. `LEARCredentialEmployee`) resolve to their versioned profile, and applies the canonical W3C VCDM default `issuer.id` to `issuerIdPath` when the schema does not declare `validation.issuer_id_path`. Sample profiles matching `*.sample*.json` are skipped.
- **`LocalTrustedIssuersProvider`**: when a lookup by the credential's `issuer.id` misses (e.g. DOME credentials in full DID form `did:elsi:VATES-...`), the provider strips the `did:elsi:` prefix and retries once. A single `trusted-issuers.yaml` entry per organisation (plain identifier) now covers both EUDIStack-issued and DOME-issued credentials without duplication.
- **`CertificateValidationServiceImpl.processCertificate`**: normalises the expected issuer id by stripping the `did:elsi:` prefix before matching the certificate's `organizationIdentifier` (OID `2.5.4.97`). Resolves `MismatchOrganizationIdentifierException` on DOME credentials whose JWT signs with a QTSP certificate whose DN carries only the bare VATES code.

### Fixed - 2026-06-17

- **OID4VP login bypassed the sunset flag (US-08 AC-07 / AC-10)**: prior to this branch the legacy/bumped feature flags only affected the M2M `client_credentials` grant; OID4VP user-driven logins through `/oid4vp/auth-response` skipped the dispatcher entirely and accepted any well-formed VP, so closing the legacy flag would still mint authorization codes for legacy credentials presented from a wallet. Both code paths now share the same gating point — closing `verifier.dome.legacy-read-enabled` returns `410 Gone` consistently across M2M and user-driven flows.

### Changed - 2026-06-18
- **Unified URL generation — canonical/non-canonical distinction removed**: all requests now arrive with the `/verifier` servlet context path, so `BackendConfig.getUrl()` always appends `request.getContextPath()` unconditionally. The `X-Tenant`-based branch that stripped the context path for non-canonical routes has been deleted, along with `IssuerOverrideFilter` and its test. `AuthorizationServerSettings` no longer needs a custom filter to override the issuer; Spring AS derives it correctly from the request URL. Stale test `getUrl_nonCanonical_returnsBaseWithoutContextPath` updated to reflect the new behavior.

### Fixed 2026-06-18
- **Discovery document URLs include `/verifier` for non-prefixed access**: Spring Authorization Server derives the issuer from `request.getRequestURI()`, which always includes the servlet context path (`/verifier`). For non-canonical deployments (where the external URL has no `/verifier` prefix), the discovery document URLs were incorrect. Added `IssuerOverrideFilter`, which runs after Spring AS's `AuthorizationServerContextFilter` and replaces the issuer in `AuthorizationServerContextHolder` with the value from `BackendConfig.getUrl()` — which already strips the context path when the `X-Tenant` header is present. Proxy must set `X-Tenant` for non-prefixed routes.

### Fixed - 2026-06-17
- **CORS on public discovery endpoints**: `/.well-known/**` and `/oidc/jwks` were served by the Authorization Server filter chain (highest precedence), which applied the registered-clients CORS policy and blocked cross-origin requests from unregistered origins. These endpoints are public by spec (OpenID Connect Discovery 1.0, RFC 8414, RFC 7517) and now return a wildcard CORS configuration regardless of the requesting origin.
- **Error/login redirect blocked by SSRF check**: `CustomErrorResponseHandler` was rejecting redirects to the verifier's own `/login` and `/error` pages because the verifier's origin was not in `allowedClientsOrigins`. The handler now also allows the verifier's own origin, derived dynamically from `BackendConfig.getUrl()`.

### Changed - 2026-06-17
- Enhance app URL generation to handle canonical and non-canonical requests based on X-Tenant header.

### Added - 2026-06-16

- **Tenant Resolution Header Support**: `TenantDomainFilter` now resolves the tenant from the `X-Tenant` request header first, validating and normalizing the value to lowercase before storing it as a request attribute and in the MDC. If the header is missing, blank, or invalid, tenant resolution falls back to the first valid hostname segment obtained from `request.getServerName()`. Added the `X_TENANT_HEADER` constant to `Constants`.
- Build `allowedClientsOrigins` from registered redirect URIs to support multi-domain clients like DOME.
- Validate certificate chain
- Improved GDPR compliance by reducing PII logging.

## [3.1.7] - 2026-06-09

### Fixed

- **Cryptographic Binding**: `validateCryptographicBinding()` now follows a priority fallback chain instead of failing immediately when `cnf.jwk` is absent. Chain: (1) `cnf.jwk` — direct JWK Thumbprint comparison (RFC 7638), (2) `cnf.kid` — DID resolution via `DIDService` + thumbprint, (3) `credentialSubject.mandate.mandatee.id` — DID resolution via `DIDService` + thumbprint. Supports both W3C (`credentialSubject.mandate.mandatee.id`) and SD-JWT flat (`mandate.mandatee.id`) credential formats.

## [3.1.6] - 2026-05-28

### Added
- Add support deferred critical extensions in JWS verification

## [3.1.5] - 2026-05-12

### Fixed

- Extract mandator organization identifier without trust framework call

## [3.1.4] - 2026-05-12

### Changed
- **Authorization Flow**: Updated the `authorization-request` logic to support metadata transmission.
- **ClientMetadata:** Updated the `clientMetadata` structure to align with the latest metadata specifications and requirements.
- **Testing:** Updated existing tests to validate the integrity of the updated `clientMetadata` and authorization workflows.

### Fixed

- Implemented a custom Logback `PatternLayout` (`MaskingPatternLayout`) for the `CONSOLE` appender to redact PII and secrets in application logs (emails, JWTs, Bearer tokens, `tx_code`, `access_token`, `refresh_token`, passwords and `secret`).
- Avoid cryptographic binding validation for client credentials presentation.

## [3.1.3] - 2026-04-23

### Changed

- **CI deploy health check is now warning-only**: `deploy.yml` was failing the deploy on non-200 responses, but the configured host (`verifier-stg.api.altia.eudistack.net`) does not resolve from the GitHub runner — `altia` is not published in Route53, only tenant subdomains (`<tenant>-stg.eudistack.net`) go through CloudFront. The issuer workflow has always treated the same condition as a warning, which is why its deploys kept "passing". Aligned the verifier step to emit `::warning::` instead of `::error::` + `exit 1`, so a broken post-deploy probe no longer blocks rollouts while the real target-group health check (managed by `aws ecs wait services-stable`) keeps validating task health. True end-to-end validation should be performed manually against `https://<tenant>-stg.eudistack.net/verifier/health`.

## [3.1.2] - 2026-04-23

### Fixed

- **CI deploy health check**: `deploy.yml` probed `https://verifier-<env>.api.altia.eudistack.net/health`, but the ALB only routes `/verifier/*` to the verifier target group and Spring exposes the endpoint at `/verifier/health` (context-path introduced in 3.1.0). The health step returned HTTP 000 for five attempts and failed the deploy. Updated `HEALTH_URL` to `/verifier/health`.

## [3.1.1] - 2026-04-23

### Changed

- **`application.yaml`**: `server.forward-headers-strategy: framework` remains hardcoded, but the matching `SERVER_FORWARD_HEADERS_STRATEGY` env var has been removed from the ECS task definition in `eudistack-platform-iac` to eliminate redundancy. Behaviour unchanged.

### Fixed

- `PublicCorsConfigTest`: aligned assertion with production config that includes `Cache-Control` in allowed headers (added in 3.0.3). CI `:test` task was failing with `expected: <[Content-Type, Authorization]> but was: <[Content-Type, Authorization, Cache-Control]>`.

## [3.1.0] - 2026-04-20

### Fixed (EUDI-064: AWS deployment readiness) — Verifier context-path

- **AWS deployment readiness (CloudFront + ALB, no nginx):** previously the verifier relied on nginx to strip the `/verifier/` prefix before forwarding requests; Spring controllers were mapped without the prefix (e.g. `@RequestMapping("/api/login")`). On AWS, requests arrive at the pod with `/verifier/...` intact and Spring did not match them.
  - `application.yaml`: added `server.servlet.context-path: ${APP_CONTEXT_PATH:/verifier}` so Spring itself handles the prefix. The default keeps local dev via nginx working (nginx still forwards with the prefix) and AWS direct routing works without extra infrastructure.
  - `CustomAuthorizationRequestConverter`: replaced hardcoded `"/verifier/login"` and `"/verifier/error"` strings with dynamic construction from `HttpServletRequest.getContextPath()`. The value is captured in `convert()` and propagated through `AuthorizationContext` so login and error redirect URLs honour whatever context-path is active.
  - `SecurityHeadersFilter` and `RateLimitFilter` now strip the context-path before matching request URIs, so security headers and rate limiting work consistently regardless of the active context-path.
  - OID4VP / OIDC endpoints moved under `/verifier/` (Spring Authorization Server auto-prepends the context-path).
  - Added two unit tests verifying that the login and error redirect URLs are built from the request's context-path and contain no hardcoded `/verifier` segment. Full suite: 497 tests pass.

## [3.0.3] - 2026-04-15

### Added

- Added `Cache-Control` to allowed headers in `PublicCorsConfig` to support caching directives from wallets and prevent CORS errors on certain requests (e.g. VP submission with cache hints).

## [3.0.2] - 2026-04-15

### Added

- **EUDI-033:** Optional `loginPageUri` field in OIDC client registry for custom login page redirects
- SSE event notifications for VP validation failures (error feedback to frontend)

## [3.0.1] - 2026-04-13

### Added

- **EUDI-013:** Dual VCDM v1.1/v2.0 credential extraction in `extractVCFromPayload()` — detects format by presence of `vc` claim
- **EUDI-013:** Legacy schema profiles for `LEARCredentialEmployee` and `LEARCredentialMachine` (DOME v2-v3 backward compatibility)
- **EUDI-013:** DCQL queries for legacy credential types alongside new `.w3c.4`/`.w3c.3` types
- RSA key support in `CertificateValidationServiceImpl` for W3C VP path (QTSP compatibility)
- RSA minimum key size enforcement (reject < 2048 bits, warn 2048-3072)
- **Nested SD-JWT verification (RFC 9901)** — `SdJwtVerificationServiceImpl` recursively resolves `_sd` arrays at any nesting depth. Supports mandate wrapper structure. (EUDI-012)
- **Empty path embed resolution** — `SchemaProfileClaimsExtractor` supports empty path to embed the full credential as `vc` claim in access tokens for DOME compatibility. (EUDI-033)

### Fixed

- **SD-JWT issuer signature: x5c takes priority over DID resolution (EUDISTACK-154)** — When the SD-JWT `iss` claim started with `did:` (e.g. `did:elsi:VATES-...`) but the JWT was signed via QTSP with an `x5c` certificate chain in the header, the verifier attempted DID resolution first and failed because only `did:key` is supported. Now `x5c` takes priority when present, falling back to DID only when no certificate chain exists.
- **Error logging includes exception message** — `ErrorResponseFactory` now logs `ex.getMessage()` alongside the error type, making 401 failures diagnosable from logs without reproducing.
- **Issuer identification uses profile `issuer_id_path`** — `VpServiceImpl` now resolves the issuer ID from the schema profile path (e.g. `issuer.organizationIdentifier` for W3C, `iss` for SD-JWT) instead of the JWT `iss` claim. Previously `extractIssFromJwt()` returned `did:elsi:VATES-...` which didn't match the trusted issuers list. Removed `extractIssFromJwt()`.
- **RSA key rejection in BitstringStatusListVerifier** — `CertificateValidationServiceImpl.verifyJWTSignature` now accepts both EC and RSA public keys. Previously only EC was accepted, causing Status List Credential validation to fail when the issuer signs with an RSA certificate.

### Removed

- **Dead embedded schemas** — Removed `src/main/resources/schemas/LEARCredential*.jwt_vc_json.v*.json` files (old naming convention, never resolved by `LocalSchemaResolver`).
- **Embedded local/ fallback** — Removed `src/main/resources/local/` directory (`clients.yaml`, `trusted-issuers.yaml`). All configuration is mounted externally via Docker volumes.

### Changed

- **DCQL profiles simplified** — Reduced to two scopes (`learcredential`, `doctorid`) instead of redundant `learcredential.employee`/`learcredential.machine` sub-profiles.
- **EUDI-013:** Rename credential type IDs: `learcredential.employee.w3c.1` → `.w3c.4`, `learcredential.machine.w3c.1` → `.w3c.3`
- **EUDI-013:** `extractIssFromJwt()` now supports v2.0 issuer property (string or object) in addition to JWT `iss` claim
- **Actuator config migrated to Spring Boot 3.5 `access` API** — Replace deprecated `enabled-by-default: false` / `enabled: true` with `access: none` / `access: unrestricted`.
- **Health probes enabled** — Added `liveness` and `readiness` state indicators. Parameterized `show-details` via `MANAGEMENT_HEALTH_SHOW_DETAILS` env var (default: `when-authorized`).

## [3.0.0] - 2026-03-24

### Security

- **PKCE S256 enforced** — PLAIN method rejected per HAIP / RFC 7636 §4.2 (S1).
- **Revocation fail-closed** — Credential rejected if revocation status cannot be determined, both JWT VP and SD-JWT paths (S2).
- **Cache DoS protection** — All `CacheStore` instances bounded with `maximumSize(10000)` (S3/F5).
- **Per-IP rate limiting** — `RateLimitFilter` with 120 req/min general, 30 req/min on auth endpoints, atomic counters (S4).
- **Token Status List signature verification** — JWT signature verified via x5c or DID before trusting status data (S5).
- **Health endpoint hardened** — `show-details: when-authorized` (S6).
- **Open redirect prevention** — `CustomErrorResponseHandler` validates redirect URI against portal domain (S7).
- **ES256 preferred, RSA accepted** — `SdJwtVerificationServiceImpl` and `TokenStatusListVerifier` accept both EC (ES256) and RSA (RS256/PS256) signatures for QTSP compatibility (S8). See _RSA deprecation plan_ below.
- **SSRF bypass for local dev** — `verifier.ssrf.allow-private` property (default `false`) disables private/loopback IP checks in `SafeUrlValidator`. Required for local dev because `*.127.0.0.1.nip.io` resolves to loopback. **Must remain `false` in production** (S14).
- **Log sanitization** — Authorization codes truncated, DN/keys/JWKS not logged at INFO, state truncated in SSE logs (S9/F4).
- **Input validation** — `@Validated` + `@NotBlank` / `@Size` on `Oid4vpController` parameters (F1).
- **Security headers** — `SecurityHeadersFilter` adds HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy, conditional Cache-Control (F2).
- **Error message leak prevention** — All `GlobalExceptionHandler` methods use `handleSafe`; `handleWith` removed from `ErrorResponseFactory` (F3/O1).
- **SSE connection limit** — `SseEmitterStore` bounded at 5000 concurrent emitters (F6).
- **Refresh token rotation** — Token invalidated on use in `CustomTokenRequestConverter` (F10).
- **Swagger UI disabled by default** — Controlled via `SPRINGDOC_ENABLED` env var (F8).
- **Validation exception handlers** — `ConstraintViolationException` and `HandlerMethodValidationException` return 400 (W6).
- **Dependency updates** — `org.json` 20230227→20240303, `jackson-dataformat-yaml` 2.17.2→2.18.2 (F7).

### Added
- **Schema-agnostic credential pipeline** — `GenericCredential(JsonNode, SchemaProfile)` replaces all typed LEARCredential POJOs. Validation, claims extraction, revocation, and M2M eligibility are driven by `.profile.json` files. Adding a new credential type requires zero Java code (EUDI-020 FR-10).
- **Profile-driven validation metadata** — `SchemaProfile` extended with `ValidationPaths`, `RevocationPaths`, `grantEligibility`, `schemaRequired`, `issuerIdPath`, `mandatorOrgIdPath`. All `.profile.json` files updated.
- **Classpath schema auto-discovery** — `LocalSchemaProfileRegistry` scans `classpath:schemas/*.json` automatically via `ResourcePatternResolver`. No hardcoded filename arrays.
- **JSON Schema validation in VP pipeline** — `CredentialValidator` wired into `VpServiceImpl` as Step 2b. Schema failures throw `CredentialSchemaValidationException`.
- **OID4VP `client_metadata`** — Authorization Request JWT includes `client_metadata` with `vp_formats_supported` (ES256 for `dc+sd-jwt` and `jwt_vc_json`) when client_id uses `x509_hash:` or `did:` prefix (OID4VP §5.1) (EUDI-020 FR-05).
- **OpenAPI annotations** — `@Tag`, `@Operation`, `@ApiResponse`, `@Parameter` on all 4 custom endpoints. `@Schema` on response models. Swagger UI at `/swagger-ui.html` (EUDI-020 FR-07).
- **CORS policy tests** — 28 tests: integration tests for public endpoint wildcard CORS, unit tests for `PublicCorsConfig` and `RegisteredClientsCorsConfig` (EUDI-020 FR-08).
- **Tenant claim in access token** — Signed `tenant` claim in JWT access token from OIDC client registration (EUDI-017 Phase A).
- **DCQL query support** — SD-JWT VC credential queries using DCQL for OID4VP 1.0 compliance.
- **SD-JWT VC verification** — Full SD-JWT VC (RFC 9901) verification pipeline with selective disclosure validation.

### Removed
- **LEARCredential typed models** — Deleted entire `lear/` model hierarchy (39 Java files), `LEARCredentialType` enum, `CredentialMapperService`, `IssuerDeserializer`, `Issuer`/`SimpleIssuer`/`DetailedIssuer` — replaced by `GenericCredential` (EUDI-020 FR-10).
- **Hardcoded M2M type checks** — `MACHINE_CONFIG_IDS` set and `startsWith("learcredential.machine.")` replaced by profile-driven `grant_eligibility` (EUDI-020 FR-10).
- **Hardcoded constants** — `LOGIN_TIMEOUT`, `LOGIN_TIMEOUT_CHRONO_UNIT`, `IS_NONCE_REQUIRED_ON_FAPI_PROFILE` removed from `Constants.java` (EUDI-020 FR-06).

### Changed
- **VP validation pipeline** — `VpServiceImpl` uses `GenericCredentialFactory` + profile-driven paths for time window, revocation, issuer org ID, and mandator validation. Mandator check is conditional on profile configuration (EUDI-020 FR-10).
- **Configurable login timeout and FAPI nonce** — `verifier.backend.login-timeout-seconds` and `fapi-nonce-required` in `application.yaml` with env var overrides (EUDI-020 FR-06).
- **Credential type detection** — Switched from hardcoded type strings to `credential_configuration_id` pattern.
- **Token claim extraction** — Refactored `CredentialClaimsExtractor` to support both W3C and SD-JWT VC formats.
- **JTI replay cache** — `JtiTokenCache` now uses `CacheStore<String>` with TTL-based expiry (1800s) instead of unbounded `HashSet`.
- **OID4VP authorization request** — `aud` set to `https://self-issued.me/v2` per OID4VP §5.8; `client_id_scheme` removed per §5.9.
- **Virtual threads** — Enabled Spring virtual threads for I/O-bound operations.

## [v2.1.0] - 2026-02-27

### Added
- **Hexagonal architecture**: Reorganized entire codebase into 2 bounded contexts (`verifier/`, `oauth2/`) + `shared/` module with ports & adapters pattern.
- **Application workflows**: Extracted business logic from OAuth2 filters into testable workflow classes (AuthorizationRequestBuildWorkflow, TokenGenerationWorkflow, ClientCredentialsValidationWorkflow, VerifyPresentationWorkflow).
- **External file injection**: Clients YAML, trusted issuers YAML, and JSON Schemas can now be injected via Docker volumes or Kubernetes ConfigMaps without rebuilding the image (`VERIFIER_BACKEND_LOCALFILES_CLIENTSPATH`, `VERIFIER_BACKEND_SSO_CONFIG_PATH`, `VERIFIER_BACKEND_LOCALFILES_TRUSTEDISSUERSPATH`, `VERIFIER_BACKEND_LOCALFILES_SCHEMASDIR`).
- **ArchUnit enforcement**: 17 architecture rules validating hexagonal layers, bounded context isolation, naming conventions, and dependency constraints.
- **Deployment guide**: Comprehensive deployment documentation at `.claude/docs/deployment.md`.
- **SSE login notification**: New `SseEmitterStore` + `LoginSseController` (`/api/login/events?state=...`) replaces WebSocket for cross-device QR login flow.
- **External frontend support**: New `VERIFIER_FRONTEND_PORTALURL` config property. `CustomAuthorizationRequestConverter` redirects to external Angular SPA instead of embedded Thymeleaf pages.
- **Portal CORS**: New `PortalCorsConfig` allows the external SPA (`portalUrl`) to access `/api/login/**` endpoints.

### Changed
- **Java 17 -> 25**: Updated to Java 25 with Eclipse Temurin runtime.
- **Gradle 8.8 -> 9.1.0**: Updated build tool and wrapper.
- **Spring Boot 3.3.2 -> 3.5.11**: Major framework upgrade.
- **Dockerfile**: `gradle:9.1.0-jdk25` build stage + `eclipse-temurin:25-jre-alpine` runtime.
- **OAuth2 filters slimmed down**: CustomAuthorizationRequestConverter (524->250 lines), CustomAuthenticationProvider (392->200 lines), CustomTokenRequestConverter (229->150 lines) — all delegate to application workflows.
- **ArchUnit 1.3.0 -> 1.4.1**: Java 25 bytecode support.
- **OWASP dependency-check 9.1.0 -> 12.2.0**, SonarQube plugin 5.1.0 -> 6.0.1, Swagger 2.2.22 -> 2.2.28.
- **AuthorizationResponseProcessorServiceImpl**: `SimpMessagingTemplate` replaced by `SseEmitterStore.send(state, redirectUrl)`.
- **FrontendProperties**: Simplified to a single `portalUrl` field. Colors, assets, URLs, and defaultLang moved to Angular SPA `theme.json`.

### Removed
- **Thymeleaf**: Removed `spring-boot-starter-thymeleaf`, 6 HTML templates (login-en/es/ca, client-authentication-error-en/es/ca), all static CSS/JS/images.
- **WebSocket**: Removed `spring-boot-starter-websocket`, `WebSocketConfig`, SockJS/STOMP infrastructure.
- **QR server-side**: Removed `com.github.kenglxn.QRGen`, `LoginQrController`, `QRCodeGenerationException`. QR is now generated client-side by the Angular SPA.
- **ClientErrorController**: Error page now served by Angular SPA at `{portalUrl}/error`.

## [v2.0.12](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.12)

### Changed

- Read bitstring-encoded lists using MSB-first ordering.

## [v2.0.11](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.11)

### Added

- Add support for BitstringStatusListEntry credential status type.

## [v2.0.10](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.10)
### Added
- Added support for cryptographic binding

## [v2.0.9](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.9)
### Changed
- In login template, enhance logo responsiveness.

## [v2.0.8](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.8)
### Changed
- In login template, change 'dark-primary' variable name to 'secondary', and remove QR padding.

## [v2.0.7](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.7)
### Changed
- - Resolve logo and favicon URLs dynamically using a configurable images base URL and paths.

## [v2.0.6](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.6)
### Added
- Altia and ISBE favicons.

### Changed
- Rename DOME favicon.

## [v2.0.5](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.5)
### Fixed
- Small text fixes in login template. 

## [v2.0.4](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.4)
### Removed
- Remove hardcoded visible "DOME" references in UI.

## [v2.0.3](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.3)
### Changed
- For frontend pages, set language from Accept-Language header before using default language.

## [v2.0.2](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.2)
### Added
- Get default language from configuration, use it to translate HTML templates.

## [v2.0.1](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.1)
- ### Added
- Implement Authorization Code Flow with PKCE

## [v2.0.0](https://github.com/in2workspace/in2-verifier-api/releases/tag/v2.0.0)
- New major version to align with the new major version of EUDIStack project.

## [v1.3.11](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.10)
### Added
- Added revocation function for new credentials with credentialStatus.
- Test for verify that is working the revocation

## [v1.3.10](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.10)
### Added
- Added access for prometheus at spring security at matcher.

## [v1.3.9](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.9)
### Added
- Added access for prometheus at spring security.

## [v1.3.8](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.8)
### Added
- Validated audience and nonce for OpenID4VP.
- Added specific OpenID4VP exceptions.
- Handled type claim in Authorization Request.

## [v1.3.7](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.7)
### Fixed
- Modify the response token according to the grant type (client_credentials should not include id_token or 
refresh_token).
- Set the scopes profile and email in the response id_token, regardless of whether they are sent in the request.
- Change the client_id_schema to did:key in the authorization request.
- Modify the client_id in the response access_token so that it returns the URL.
- Add LEARCredentialMachine.
- Extract DID Key as environment variable.

## [v1.3.6](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.6)
### Fixed
- Add compatibility on LEARCredentialEmployee v2.0 for LEARCredential v1.0 claims

## [v1.3.5](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.5)
### Fixed
- Problem related to the M2M vp_token validation

## [v1.3.4](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.4)
### Fixed
- Problem logging in with token when the login time has run out.

## [v1.3.3](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.3)
### Fixed
- Problem with issuer serialization

## [v1.3.2](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.2)
### Fixed
- Access token timeout

## [v1.3.1](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.1)
### Fixed
- Error on JsonProperty annotation in the LEARCredential

## [v1.3.0](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.3.0)
### Added
- Compatibility for LEARCredentialEmployee v2.0

## [v1.2.1](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.2.1)
### Modified
- Updated DOME Logo

## [v1.2.0](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.2.0)
### Modified
- Updated Login page UI
- Refactor configuration parameters: removed unnecessary ones and grouped internal ones into frontend/backend categories.

## [v1.1.0](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.1.0)
### Added
- Add refresh token support for the OpenID Connect flow
- Add nonce support for the OpenID Connect authorization code flow

## [v1.0.17](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.17)
### Added
- Add documentation for OIDC client registration and interaction with the verifier.

## [v1.0.16](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.16)
### Fixed
- Add time window validation for the credential in the Verifiable Presentation

## [v1.0.15](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.15)
### Fixed
- Fix token serialization issue
- Add cors config for registered clients

## [v1.0.14](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.14)
### Fixed
- Rename the verifiableCredential claim of the access token to vc

## [v1.0.13](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.13)
### Fixed
- Fix contact us link not working

## [v1.0.12](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.12)
### Fixed
- Unauthorized Http response code for failed validation of VP token

## [v1.0.11](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.11)
### Fixed
- Add cors configuration to allow requests from external wallets, on the endpoints the wallet use.

## [v1.0.10](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.10)
### Fixed
- Add an error page for errors during the client authentication request.

## [v1.0.9](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.9)
### Fixed
- Fix images url
- Fix spacing between navbar and content for tablets width range

## [v1.0.8](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.8)
### Fixed
- Fix color contrast 
- Use brand colors, font and favicon
- Fix layout responsiveness

## [v1.0.7](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.7)
### Fixed
- Fix the JWKS endpoint response to use the claim `use` with `sig` value.

## [v1.0.6](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.6)
### Fixed
- Authentication request fix to comply with the OpenID Connect Core standard.

## [v1.0.5](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.5)
### Fixed
- Token response fix to comply with the OpenID Connect Core standard.

## [v1.0.4](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.4)
### Fixed
- Fix security issue with the signature verification.

## [v1.0.3](https://github.com/in2workspace/in2-verifier-api/releases/tag/v1.0.3)
### Added
- Support for OpenID Connect.
  - Only uses Authentication using the Authorization Code Flow (without PKCE).
  - Only uses Claims with Requesting Claims using Scope Values (openid learcredential)
  - Only uses Passing Request Parameters as JWTs (Passing a Request Object by Reference).
  - Only use Client Authentication method with Private Key JWT.
  - Only uses for P-256 ECDSA keys for Signing Access Token.
- Support for OpenID for Verifiable Presentations (OID4VP).
  - Implement VP Proof of Possession verification.
  - Implement Issuers, Participants and Services verification against the DOME Trust Framework.
  - Implement VC verification against the DOME Revoked Credentials List.
- Support FAPI
  - Only use request_uri as a REQUIRED claim in the Authentication Request Object.
- Implement DOME Human-To-Machine (H2M) authentication.
  - Implement Login page with QR code.
- Implement DOME Machine-To-Machine (M2M) authentication.
- Integrate with the DOME Trust Framework.

### Fixed
- Fix the issue with Login page not showing Wallet URL.
- Fix the issue with Login page not valid Registration URL.
- Fix the issue with Login page not redirecting to the Relying Party after expiration of the QR code.
