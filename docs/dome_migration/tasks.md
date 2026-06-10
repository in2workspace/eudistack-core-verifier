# EUDISTACK-145: US-08 Verifier dual-format read (legacy + bumpeado) — Tasks (per-Story)

> **Naturaleza del documento.** Este `tasks.md` pertenece a la Story `EUDISTACK-145` del feature parent `EUDISTACK-12`. Generado por `task-planner` dentro de `/enrich-us EUDISTACK-145` (Stage 2b). Consumido por `fullstack-developer` dentro de `/implement EUDISTACK-145 eudistack-core-verifier feature/EUDISTACK-145-verifier-dual-format-read`.

## Status

| Field | Value |
|-------|-------|
| Feature parent | EUDISTACK-12 — DOME — Standalone-to-SaaS Tenant Migration |
| Story | EUDISTACK-145 — US-08: Verifier dual-format read (legacy + bumpeado) con sunset 6–12m |
| Story folder | `docs/EUDISTACK-12-dome-migration/EUDISTACK-145/` |
| Target repo | `eudistack-core-verifier` |
| Branch | `feature/EUDISTACK-145-verifier-dual-format-read` |
| Current version | `3.1.5` |
| Target version | `3.1.5` (determinado en C5 — ASK USER) |
| Tech design (per-Story) | [`technical-design.md`](technical-design.md) |
| Acceptance criteria (canonical) | [`acceptance-criteria.md`](acceptance-criteria.md) |
| Feature architecture (transversal) | [`../specs/architecture.md`](../specs/architecture.md) |
| Feature SRS (transversal) | [`../specs/srs.md`](../specs/srs.md) |

---

## Tasks

| # | Task | Scope | Files | AC | Depends on | Size | Status |
|---|------|-------|-------|----|------------|------|--------|
| 1 | Definir modelos de dominio del dispatcher: `DispatchDecision`, `DispatchRule`, enums `CredentialFormat` y `DispatchReason` | domain | `verifier/domain/model/dispatch/DispatchDecision.java`, `DispatchRule.java`, `CredentialFormat.java`, `DispatchReason.java` | AC-01, AC-02, AC-03, AC-04, AC-10 | — | S | done |
| 2 | Ampliar `SchemaProfile` con campo `wrapVcInAccessToken` (default `false`; no rompe profiles existentes) | domain | `verifier/domain/model/validation/SchemaProfile.java` | AC-02, AC-04, AC-06, AC-09 | 1 | S | done |
| 3 | Añadir excepciones de dominio: `LegacyFormatSunsetClosedException` (→ 410), `BumpedFormatTemporarilyDisabledException` (→ 503), `UnknownCredentialFormatException` (→ 400) | domain | `verifier/domain/exception/LegacyFormatSunsetClosedException.java`, `BumpedFormatTemporarilyDisabledException.java`, `UnknownCredentialFormatException.java` | AC-07, AC-10, ES-03, ES-04, ES-05 | 1 | S | done |
| 4 | Definir ports de dominio: `CredentialSchemaDispatcher` (interfaz), `CredentialReader` (SPI con `supports`+`read`), `AccessTokenBuilder` (interfaz) + value object `ReaderResult` y `BuildContext` | domain | `verifier/domain/service/CredentialSchemaDispatcher.java`, `CredentialReader.java`, `AccessTokenBuilder.java`, `verifier/domain/model/tokens/ReaderResult.java`, `BuildContext.java` | AC-01, AC-02, AC-05, AC-06, AC-09 | 1, 2, 3 | M | done |
| 5 | Configuración Spring: `DispatchProperties` (`@ConfigurationProperties("verifier.dispatch")`) + `DispatchConfiguration` que registra `List<DispatchRule>` desde `application.yaml`; actualizar `application.yaml` con sección `verifier.dispatch.rules.legacy/bumped` + defaults de flags | infrastructure | `shared/config/properties/DispatchProperties.java`, `verifier/infrastructure/config/DispatchConfiguration.java`, `resources/application.yaml` | AC-08, AC-10 | 1, 4 | S | done |
| 6 | Implementar `ContextAndTypeCredentialSchemaDispatcher`: lógica determinista `type[]`-primario/`@context`-fallback, consulta flags desde `TenantConfigPort`, lanza excepciones de sunset/desactivación; actualizar `TenantDomeConfigProperties` con flags `legacyReadEnabled`/`bumpedReadEnabled` | infrastructure | `verifier/infrastructure/adapter/dispatch/ContextAndTypeCredentialSchemaDispatcher.java`, `shared/config/properties/TenantDomeConfigProperties.java` | AC-01, AC-02, AC-03, AC-04, AC-07, AC-08, AC-10, EC-01, EC-02, EC-03, ES-01, ES-02, ES-03, ES-04, ES-05 | 4, 5 | M | done |
| 7 | Implementar `LegacyCredentialReader`: extrae payload del wrap `vc` ya presente en la credencial v1.1, delega extracción de claims al `ClaimsExtractor` existente, produce `ReaderResult` con `wrapVcInAccessToken=false` | infrastructure | `verifier/infrastructure/adapter/dispatch/LegacyCredentialReader.java` | AC-01, AC-03, AC-05 | 4 | S | done |
| 8 | Implementar `BumpedCredentialReader`: lee credencial v2.0 como payload raíz, resuelve `SchemaProfile` desde `SchemaProfileRegistry`, produce `ReaderResult` con `wrapVcInAccessToken=true`; lanza `InvalidCredentialTypeException` ante profile ausente (fail-secure EC-07) | infrastructure | `verifier/infrastructure/adapter/dispatch/BumpedCredentialReader.java` | AC-02, AC-04, AC-06, EC-07, ES-08 | 4 | S | done |
| 9 | Implementar `JwsAccessTokenBuilder`: construye JWT del Access Token con wrap `vc` condicional según `profile.wrapVcInAccessToken()`; reutiliza `JWTService.issueJWT`; garantiza indistinguibilidad de claims raíz entre legacy y bumped | infrastructure | `verifier/infrastructure/adapter/tokens/JwsAccessTokenBuilder.java` | AC-01, AC-02, AC-09 | 4, 7, 8 | M | done |
| 10 | Modificar `VerifyPresentationWorkflow`: invocar `CredentialSchemaDispatcher.dispatch()` tras extraer la credencial del VP; propagar `DispatchDecision` hacia `TokenGenerationWorkflow` | application | `verifier/application/workflow/VerifyPresentationWorkflow.java` | AC-01, AC-02, AC-03, AC-04, AC-05, AC-06 | 4, 6 | M | done |
| 11 | Modificar `TokenGenerationWorkflow`: delegar construcción del Access Token a `AccessTokenBuilder`; no mover construcción del id_token (permanece en el workflow); añadir llamada a `SchemaProfileRegistry.findByConfigId` con el config-id de la `DispatchDecision` | application | `oauth2/application/workflow/TokenGenerationWorkflow.java` | AC-01, AC-02, AC-09 | 9, 10 | M | done |
| 12 | Modificar `ClientCredentialsValidationWorkflow` (mínimo): invocar dispatcher para enriquecer logs/métricas del flujo M2M; no cambiar lógica de `grantEligibility` | application | `oauth2/application/workflow/ClientCredentialsValidationWorkflow.java` | AC-05, AC-06, EC-06 | 6, 10 | S | done |
| 13 | Añadir `DomeDispatchExceptionHandler` (`@RestControllerAdvice`): mapea las 3 nuevas excepciones a Problem+JSON RFC 9457 (`410 Gone`, `503 Service Unavailable`, `400 Bad Request`) | infrastructure | `shared/domain/exception/handler/DomeDispatchExceptionHandler.java` | AC-07, ES-03, ES-04, ES-05, ES-08 | 3 | S | done |
| 14 | Instrumentar métricas Micrometer: contador `dome_verifier_dispatcher_total{tenant,format,decision,reason}` en el dispatcher; contador `dome_verifier_legacy_replay_after_sunset_total{tenant}` en el handler 410; histograma `dome_verifier_dispatcher_duration_ms` | infrastructure | `verifier/infrastructure/adapter/dispatch/ContextAndTypeCredentialSchemaDispatcher.java`, `DomeDispatchExceptionHandler.java` | AC-01, AC-02, AC-07, NFR-S-145-01, NFR-S-145-02 | 6, 13 | S | done |
| 15 | Crear fixtures de test `DomeCredentialFixtureFactory` + vectores sintéticos firmados (Nimbus JOSE) para los 6 config-ids DOME bajo `src/test/resources/fixtures/dome/` | test | `src/test/java/.../verifier/dualformat/DomeCredentialFixtureFactory.java`, `src/test/resources/fixtures/dome/*.json` | todos los AC | 7, 8 | M | done |
| 16 | Tests unitarios del dispatcher `CredentialSchemaDispatcherTest`: cubrir EC-01 (contexto mixto resuelto por type), EC-02 (sin URL VCDM resuelto por type), EC-03 (type[] orden no canónico), ES-01 (`@context` ausente → 400), ES-02 (solo genéricos → 400), ES-03 (config-id desconocido → 400), ES-08 (reader lanza excepción → fail-secure sin cascada) | test | `src/test/java/.../verifier/domain/service/CredentialSchemaDispatcherTest.java` | EC-01, EC-02, EC-03, ES-01, ES-02, ES-03, ES-08 | 15 | M | done |
| 17 | Tests unitarios de readers y builder: `LegacyCredentialReaderTest` (happy path v1.1, wrap ya presente), `BumpedCredentialReaderTest` (happy path v2.0, profile absent → excepción), `JwsAccessTokenBuilderTest` (snapshot indistinguibilidad claims raíz AC-09) | test | `src/test/java/.../verifier/infrastructure/adapter/dispatch/LegacyCredentialReaderTest.java`, `BumpedCredentialReaderTest.java`, `src/test/java/.../verifier/infrastructure/adapter/tokens/JwsAccessTokenBuilderTest.java` | AC-09, EC-07, ES-08 | 15 | M | done |
| 18 | Test unitario defaults de flags: `FlagDefaultsTest` verifica que `DispatchProperties` carga los valores correctos desde `application.yaml` sin contexto Spring completo | test | `src/test/java/.../verifier/dualformat/FlagDefaultsTest.java` | AC-08 | 5 | S | done |
| 19 | Integration tests happy path Employee: `LegacyEmployeeDispatchIT` (AC-01, MockMvc + credencial `.3`) y `BumpedEmployeeDispatchIT` (AC-02, credencial `.4` + verify wrap `vc` aplicado por Verifier) | test | `src/test/java/.../verifier/dualformat/LegacyEmployeeDispatchIT.java`, `BumpedEmployeeDispatchIT.java` | AC-01, AC-02 | 15, 10, 11 | M | done |
| 20 | Integration tests cobertura 3 tipos productivos: `LegacyAllTypesDispatchIT` (AC-03, parametrizado `.3/.2/.1`) y `BumpedAllTypesDispatchIT` (AC-04, parametrizado `.4/.3/.2`) | test | `src/test/java/.../verifier/dualformat/LegacyAllTypesDispatchIT.java`, `BumpedAllTypesDispatchIT.java` | AC-03, AC-04 | 15, 10, 11 | M | done |
| 21 | Integration tests M2M client_credentials: `MachineLegacyClientCredentialsIT` (AC-05, grant M2M con `LEARCredentialMachine.2`) y `MachineBumpedClientCredentialsIT` (AC-06, con `.3` + verify wrap `vc`) | test | `src/test/java/.../verifier/dualformat/MachineLegacyClientCredentialsIT.java`, `MachineBumpedClientCredentialsIT.java` | AC-05, AC-06, EC-06 | 15, 12 | M | done |
| 22 | Integration test sunset y conflicto flags: `SunsetClosedIT` (AC-07 + ES-04: `legacy_read=false` → 410 Gone + audit log + contador), `LegacyOffBumpedOnIT` (AC-10: flags independientes, bumped sigue 200 OK cuando legacy OFF), `BumpedDisabledIT` (ES-05: `bumped_read=false` → 503) | test | `src/test/java/.../verifier/dualformat/SunsetClosedIT.java`, `LegacyOffBumpedOnIT.java`, `BumpedDisabledIT.java` | AC-07, AC-10, ES-04, ES-05 | 15, 6, 13 | M | done |
| 23 | Integration test caché de configuración y TTL: `TenantConfigCacheRefreshIT` (AC-08 + EC-04 flag toggle observado en ≤ TTL+5s + ES-06 stale-while-error + NFR-S-145-03) | test | `src/test/java/.../verifier/dualformat/TenantConfigCacheRefreshIT.java` | AC-08, EC-04, ES-06, NFR-S-145-03 | 5, 6 | M | done |
| 24 | Integration test indistinguibilidad Access Token: `AccessTokenStructureParityIT` (AC-09, snapshot JSONAssert de claims raíz legacy vs bumped ignorando timestamps y `jti`) | test | `src/test/java/.../verifier/dualformat/AccessTokenStructureParityIT.java` | AC-09 | 15, 19 | S | done |
| 25 | Integration tests allowlist, SchemaProfile y JWKS: `AllowlistPreservationIT` (EC-05: RP no-allowlist rechazada igual que pre-migración), `SchemaProfileGrantEligibilityBumpedIT` (EC-06: `grantEligibility` incluye `client_credentials` para Machine bumped), `CredentialSchemaDispatcherIT` (EC-07: profile ausente → 400 fail-secure), `JwksTimeoutFailureIT` (ES-07: JWKS timeout → 503) | test | `src/test/java/.../verifier/dualformat/AllowlistPreservationIT.java`, `SchemaProfileGrantEligibilityBumpedIT.java`, `CredentialSchemaDispatcherIT.java`, `JwksTimeoutFailureIT.java` | EC-05, EC-06, EC-07, ES-07 | 15, 6, 8 | M | done |
| 26 | Test regression catálogo `DispatchRule` vs JSON Schemas DOME: verifica que cada `credential_configuration_id` en los JSON Schemas de `eudistack-platform-assets` está declarado en `DispatchProperties.legacy` o `bumped` — falla CI si hay desviación (R-145-5) | test | `src/test/java/.../verifier/dualformat/DispatchRuleCatalogConsistencyTest.java` | AC-03, AC-04, AC-08 | 5 | S | done |

### Closing Tasks (siempre al final, en este orden — per-Story)

| # | Task | Scope | Details | Status |
|---|------|-------|---------|--------|
| C1 | Update CHANGELOG.md | docs | Añadir entradas bajo `[Unreleased]` en `eudistack-core-verifier/CHANGELOG.md`: dual-format read dispatcher (legacy + bumpeado), wrap `vc` en Access Token para VCDM v2.0 (FR-06a), feature flags `verifier.dome.legacy_read.enabled` / `verifier.dome.bumped_read.enabled`, sunset 410 Gone. Referencia EUDISTACK-145. | pending |
| C2 | Marcar checkboxes spec | docs | En `docs/EUDISTACK-12-dome-migration/specs/user-stories.md`, marcar `[x]` con fecha `2026-MM-DD` para los ACs de US-08 (EUDISTACK-145). | pending |
| C3 | Marcar US-08 como Done en user-stories.md | docs | En `docs/EUDISTACK-12-dome-migration/specs/user-stories.md`, actualizar `Status: Done` + `Done date: YYYY-MM-DD` de US-08. **No escribe a Jira** — el sync a Jira lo hace el usuario externamente. Excepción permitida con lock activo (junto con C2). | pending |
| C4 | Actualizar status de tasks.md | docs | Marcar todas las tasks 1–26 como `completed`. | pending |
| C5 | Version bump | release | **ASK USER** el tipo de bump (MAJOR / MINOR / PATCH). Sugerido en `technical-design.md` §4.2: **MINOR** (nuevo comportamiento dispatcher + readers sin cambios incompatibles en la API pública del Verifier). Commit separado: `chore: bump version to X.Y.Z` en `eudistack-core-verifier`. | pending |

> **Regla C5:** `fullstack-developer` DEBE preguntar al usuario qué tipo de version bump aplicar. Nunca decidir de forma autónoma.
>
> **Disciplina per-Story:** C1–C5 aplican siempre por Story. El feature parent (`EUDISTACK-12`) no tiene closing tasks propias — transiciona a `Done` cuando todas sus Stories child estén en `Done` en Jira.

---

## Orden de implementación

1. Modelos de dominio e interfaces (sin dependencias de framework): tasks 1–4
2. Configuración Spring + properties: task 5
3. Adaptadores de infraestructura (dispatcher, readers, builder, handler, métricas): tasks 6–14
4. Workflows de aplicación (modificaciones a los existentes): tasks 10–12 *(pueden solaparse con 6–14 si el equipo lo decide; la dependencia técnica es hacia las interfaces del task 4)*
5. Fixtures de test: task 15 (prerequisito de todos los integration tests)
6. Tests unitarios: tasks 16–18
7. Integration tests: tasks 19–26
8. Closing tasks: C1–C5, en orden

---

## Notas de implementación

- El Verifier usa **Spring WebMvc** (no WebFlux) — los integration tests usan `MockMvc`, no `WebTestClient`.
- El flag toggling en los integration tests de sunset/caché se gestiona con `@DynamicPropertySource` o mock de `TenantConfigPort` — **no** modificar `application.yaml` por test.
- El snapshot test de AC-09 usa `JSONAssert.assertEquals(..., JSONCompareMode.STRICT_KEY_ORDER_IGNORE)` ignorando `jti`, `iat` y `exp`.
- Las fixtures de credencial se generan **on-the-fly** con Nimbus JOSE en `DomeCredentialFixtureFactory` para evitar drift de firma. Los ficheros `.json` bajo `fixtures/dome/` son solo vectores de estructura (sin firma válida estática).
- El campo `wrapVcInAccessToken` en `SchemaProfile` es `boolean` con default `false` — garantiza compatibilidad con todos los profiles existentes que no declaren el campo.
- No tocar `ClientRegistryProvider`, `TrustFrameworkService`, `CredentialStatusVerifier`, `VpService` ni `CredentialTypeResolver` existente (allowlist preservada por inacción, EC-05).
- Task 26 (regression catálogo) debe ejecutarse en CI como parte del `./gradlew check` estándar.

> Generado durante `/enrich-us EUDISTACK-145` (Stage 2b). Actualizado durante `/implement EUDISTACK-145` según avance.
