# US-08 (EUDISTACK-145): Plan Técnico Actualizado — Síntesis Ejecutiva

**Fecha:** 2026-05-20  
**Status:** Revisión técnica completa  
**Audiencia:** Tech lead + Fullstack developer (antes de empezar implementación)

---

## 📋 Resumen de cambios vs plan inicial

### ✅ Confirmados y alineados
- **Dispatcher dual-format** → Confirmado como `CredentialSchemaDispatcher` (port)
- **Readers específicos** (Legacy + Bumped) → Confirmado con fail-secure explícito
- **AccessTokenBuilder separado** → Confirmado como port + impl `JwsAccessTokenBuilder`
- **Feature flags runtime** → Confirmado (legacy_read, bumped_read via TenantConfigPort)
- **Excepciones RFC 9457** → Confirmado (410, 503, 400)
- **Métricas Micrometer** → Confirmado
- **Allowlist preservado** → Confirmado "por inacción" (EC-05 con test)
- **M2M preservado** → Confirmado, dispatcher aplica igual

### ⚠️ Ajustes necesarios

**1. SchemaProfile.wrapVcInAccessToken**
- **Cambio:** Nuevo campo booleano (default `false`)
- **Fuente:** Asumimos viene del JSON de perfil (`.json` en `src/main/resources/schemas/`)
- **Legacy profiles:** `wrap_vc_in_access_token` omitido o `false`
- **Bumped profiles:** `wrap_vc_in_access_token: true`
- **Riesgo:** Si no se puebla correctamente, algunos tokens serán malformados
- **Mitigación:** Task 26 (regression test) valida cada profile tiene valor correcto

**2. TenantConfigPort + tenant_dome_config**
- **Cambio:** La spec los asume, pero en este repo todavía no hay una implementación visible de `TenantConfigPort` ni una capa equivalente de lectura por tenant para estos flags.
- **Status:** No confirmado en código; el diseño de flags sigue abierto.
- **Patrón reusable detectado:** `@ConfigurationProperties` para defaults, `CacheStore` para TTL bounded, y `TenantDomainFilter` para resolver el tenant de la request.
- **Campos nuevos:** `verifier.dome.legacy_read.enabled` (bool, default true), `verifier.dome.bumped_read.enabled` (bool, default true)
- **Lectura:** Debe resolverse con una abstracción nueva de configuración por tenant o una extensión explícita de la configuración existente, con caché bounded ≤60s.
- **Defaults:** `application.yaml` puede aportar defaults para dev local si no hay backend de configuración.
- **Implicación:** Task 5 no puede tratarse como simple extensión hasta definir la fuente de verdad y la cache policy de flags.

**3. ContextAndTypeCredentialSchemaDispatcher como implementación concreta**
- **Cambio:** La spec define el dispatcher como port + impl específica
- **Lógica:** Determina `@context` + `type[]` (prioridad type[] sobre context)
- **Consulta flags:** De TenantConfigPort, no hardcoded
- **Lanza excepciones:** 3 nuevas excepciones per AC
- **Reutiliza:** `CredentialTypeResolver` (ya existe)

---

## 🏗️ Arquitectura propuesta

### Flujo completo (dataflow)

```
RP/M2M → POST /oauth/token (credential en VP)
  ↓
VpService.extractCredentialFromVerifiablePresentationAsJsonNode(vp)
  ↓
VerifyPresentationWorkflow (modified):
  ├─ CredentialSchemaDispatcher.dispatch(credential) → DispatchDecision
  │   ├─ Parse @context
  │   ├─ Parse type[]
  │   ├─ CredentialTypeResolver.resolveConfigId(credential)
  │   ├─ TenantConfigPort.getVerifierDomeConfig(tenantId) [caché ≤60s]
  │   ├─ Valida flags: legacy_read_enabled, bumped_read_enabled
  │   └─ → DispatchDecision(format, configId, reason, decision)
  │       decision ∈ {permit, deny}
  │       reason ∈ {by_type, by_context, legacy_sunset_closed, bumped_disabled, format_unclassifiable}
  │
  ├─ IF decision=permit:
  │   ├─ IF format=LEGACY_V1_1:
  │   │   └─ LegacyCredentialReader.read(credential) → ReaderResult(vc, configId, wrapVcInAccessToken=false)
  │   │
  │   └─ IF format=BUMPED_V2_0:
  │       ├─ SchemaProfileRegistry.findByConfigId(configId)
  │       ├─ [Fail-secure] si profile ausente → InvalidCredentialTypeException → 400
  │       └─ BumpedCredentialReader.read(credential) → ReaderResult(vc, configId, wrapVcInAccessToken=true)
  │
  └─ IF decision=deny:
      └─ Lanza excepción correspondiente → DomeDispatchExceptionHandler → RFC 9457 response
          ├─ LegacyFormatSunsetClosedException (410)
          ├─ BumpedFormatTemporarilyDisabledException (503)
          └─ UnknownCredentialFormatException (400)

TokenGenerationWorkflow (modified mínimamente):
  ├─ issueAccessToken(credential, ReaderResult):
  │   ├─ ExtractClaims (ya existente, sin cambios)
  │   └─ AccessTokenBuilder.build(vc, configId, ReaderResult.wrapVcInAccessToken, extractedClaims, ...)
  │       └─ JwsAccessTokenBuilder (impl):
  │           ├─ IF wrapVcInAccessToken=true: payload.claim("vc", credential_object) [NUEVO]
  │           └─ IF wrapVcInAccessToken=false: payload.claim("vc", credential_string) [EXISTENTE]
  │           └─ → Access Token JWT
  │
  └─ issueIdToken(...) [sin cambios]

RPs/M2M reciben Access Token (estructura interna enriquecida, contrato externo = pre-migración)
```

### Diccionario de clases nuevas vs modificadas

| Clase | Estado | Módulo | Responsabilidad |
|-------|--------|--------|-----------------|
| `DispatchDecision` | NEW | domain/model/dispatch | Value object: (format, configId, reason, decision) |
| `DispatchRule` | NEW | domain/model/dispatch | Value object catálogo: (configId, format) |
| `CredentialFormat` enum | NEW | domain/model/dispatch | LEGACY_V1_1, BUMPED_V2_0 |
| `DispatchReason` enum | NEW | domain/model/dispatch | BY_TYPE, BY_CONTEXT, BY_TYPE_NO_VCDM_CONTEXT, LEGACY_SUNSET_CLOSED, ... |
| `CredentialSchemaDispatcher` | NEW | domain/service | **Port** (interface): `dispatch(JsonNode credential) → DispatchDecision` |
| `ContextAndTypeCredentialSchemaDispatcher` | NEW | infrastructure/adapter/dispatch | **Impl** del port: lógica determinista @context + type[], consulta flags, lanza excepciones |
| `LegacyCredentialReader` | NEW | infrastructure/adapter/dispatch | Lee v1.1 con wrap vc nativo, delega extracción claims |
| `BumpedCredentialReader` | NEW | infrastructure/adapter/dispatch | Lee v2.0 canónico, resuelve SchemaProfile, fail-secure si ausente |
| `ReaderResult` | NEW | domain/model/tokens | Value object: (vc, configId, wrapVcInAccessToken) |
| `AccessTokenBuilder` | NEW | domain/service | **Port** (interface): `build(...) → String JWT` |
| `JwsAccessTokenBuilder` | NEW | infrastructure/adapter/tokens | **Impl** del port: construye JWT con wrap vc condicional |
| `LegacyFormatSunsetClosedException` | NEW | domain/exception | 410 Gone — legacy deshabilitado |
| `BumpedFormatTemporarilyDisabledException` | NEW | domain/exception | 503 Service Unavailable — bumped deshabilitado |
| `UnknownCredentialFormatException` | MODIFIED | domain/exception | Reutilizar existente o extender para dual-format |
| `DomeDispatchExceptionHandler` | NEW | infrastructure/exception/handler | @RestControllerAdvice, mapea 3 excepciones → RFC 9457 |
| `SchemaProfile` | MODIFIED | domain/model/validation | Añadir `boolean wrapVcInAccessToken` (default false) |
| `DispatchProperties` | NEW | shared/config/properties | @ConfigurationProperties("verifier.dispatch"), catálogo DispatchRules |
| `TenantDomeConfigProperties` | NEW | shared/config/properties | Flags legacy_read, bumped_read (defaults desde application.yaml) |
| `VerifyPresentationWorkflow` | MODIFIED | application/workflow | Invocar dispatcher tras extraer credencial del VP |
| `TokenGenerationWorkflow` | MODIFIED | application/workflow | Delegar construcción AccessToken a builder (mínimo) |
| `ClientCredentialsValidationWorkflow` | MODIFIED (opcional) | application/workflow | Invocar dispatcher para enriquecimiento log/métrica (no lógica core) |

---

## 🎯 Decisiones críticas ya tomadas por la spec

| # | Decisión | Justificación | Riesgo |
|---|----------|---------------|--------|
| 1 | **Prioridad @context vs type[]:** type[] gana | Discrimina más precisamente; @context solo fallback | Si ambos dan config-id diferente → log WARN + métrica |
| 2 | **Wrap vc condicionado por `wrapVcInAccessToken`** | Legacy already wrapped, bumped wraps en builder | Si profiles tienen valor incorrecto → token malformado |
| 3 | **TenantConfigPort caché ≤60s** | NFR-S-145-03 requiere latencia |≤65s | Stale-while-error manejado por port (ES-06) |
| 4 | **Allowlist sin cambios (por inacción)** | Preserva NFR-02 indistinguibilidad | Si allowlist depende de config-id → regresión (EC-05 valida) |
| 5 | **M2M aplicación de dispatcher** | Flujo M2M igual que H2M | Cambio en TokenGenerationWorkflow path M2M |
| 6 | **Excepciones RFC 9457** | Standard errors, consumibles por RPs | Si mapping incorrecto → RPs no entienden error |
| 7 | **CredentialTypeResolver reutilización** | Evita duplicación lógica | Si API del resolver no expone lo que necesitamos → refactor |

---

## ❓ Ambigüedades / Puntos a aclarar ANTES de empezar implementation

### Bloqueantes (necesito respuesta antes de task 1)

1. **SchemaProfile.wrapVcInAccessToken — ¿De dónde viene el valor?**
   - A) JSON de perfil (`src/main/resources/schemas/*.json`) ← **RECOMENDADO**
   - B) Seed en BD tabla `credential_profile` (per-tenant)
   - C) Hardcoded (legacy=false, bumped=true)
   - **Impacto:** Afecta LocalSchemaProfileRegistry + seed strategy
   - **Pregunta al usuario:** Confirmar opción A

2. **TenantConfigPort / equivalente — ¿Qué abstracción usaremos para leer flags?**
  - No hay evidencia de un port dedicado en este repo, pero sí hay patrón claro para propiedades tipadas + cache local.
  - ¿Se crea un nuevo `TenantConfigPort`/`DomeTenantConfigProvider` o se amplía una capa existente?
  - ¿Qué campos expone y cómo se cachea?
  - **Impacto:** Task 5 alcance (creación nueva vs extensión)
  - **Pregunta al usuario:** Confirmar el punto exacto de lectura de flags

3. **CredentialTypeResolver.resolveConfigId() — ¿API exacta?**
   - ¿Deja `VerifiableCredential` + `VerifiableAttestation` en type[]?
   - ¿Maneja `vct` claim (SD-JWT)?
   - ¿Lanza o devuelve null si no encuentra?
   - **Impacto:** Task 6 integración
   - **Pregunta al usuario:** Revisar archivo, confirmar API

### No bloqueantes (resolubles en task correspondiente)

4. **@context + type[] conflictivos (EC-01)** → Resolver en task 6 (dispatcher)
   - Spec dice prioridad type[], pero ¿log + métrica suficiente para auditoría?

5. **Allowlist: ¿Normaliza por qué campo? (EC-05)** → Resolver en task 25 (test)
   - ¿Depende de credential_configuration_id o Subject?

6. **BumpedCredentialReader fail-secure (EC-07)** → Resolver en task 8
   - ¿Reader lanza, dispatcher captura o handler?

7. **M2M + bumped + grant_eligibility** → Resolver en task 15 (fixtures)
   - ¿Profile bumped declara `client_credentials` en grantEligibility?

---

## 📊 Matriz de responsabilidades

### CredentialSchemaDispatcher vs readers vs builder

```
┌─ CredentialSchemaDispatcher (port)
│  └─ Responsabilidad: **Discriminar** legacy vs bumped (determinista)
│     Inputs: JsonNode credential, TenantId, flags
│     Outputs: DispatchDecision(format, configId, reason)
│     No toca: readers, builders, claims
│
├─ LegacyCredentialReader (adapter)
│  └─ Responsabilidad: **Extraer vc**, preservar semántica v1.1
│     Inputs: JsonNode credential (legacy)
│     Outputs: ReaderResult(vc=credential.get("vc"), wrapVcInAccessToken=false)
│     No toca: dispatcher flags, schema resolution
│
├─ BumpedCredentialReader (adapter)
│  └─ Responsabilidad: **Validar profile**, extraer credential raíz
│     Inputs: JsonNode credential (bumped), configId
│     Outputs: ReaderResult(vc=credential_root, wrapVcInAccessToken=profile.wrapVcInAccessToken())
│     Valida: SchemaProfileRegistry.findByConfigId() → fail-secure si ausente
│     No toca: dispatcher flags
│
└─ JwsAccessTokenBuilder (adapter)
   └─ Responsabilidad: **Construir JWT** con wrap vc condicional
      Inputs: vc (from reader), ReaderResult.wrapVcInAccessToken, extractedClaims, ...
      Outputs: AccessToken JWT string
      Lógica:
        IF wrapVcInAccessToken=true: payload.claim("vc", credential_object)
        IF wrapVcInAccessToken=false: payload.claim("vc", credential_string)
      No toca: dispatcher, readers
```

---

## 🔄 Estrategia de sunset (configuración únicamente)

### Estado actual (deployment)
```yaml
verifier.dome.legacy_read_enabled = true
verifier.dome.bumped_read_enabled = true
```
→ Ambos formatos aceptados

### Estado post-sunset (6–12 meses después)
**Sin cambio de código, solo configuración:**
```sql
UPDATE tenant_dome_config 
SET verifier.dome.legacy_read_enabled = false 
WHERE tenant_id = 'dome';
```
→ Dispatcher rechaza legacy con `410 Gone`, permite bumped

### Impacto observable
- Legacy credential → 410 Gone (RFC 9457)
- Bumped credential → 200 OK (sin cambios)
- Métrica: `dome_verifier_dispatcher_total{format=legacy,decision=deny,reason=sunset_closed}` incrementa
- Sin downtime, sin redeploy

---

## 🚨 Riesgos técnicos residuales

| # | Riesgo | Severidad | Mitigación |
|---|--------|-----------|-----------|
| 1 | Cambio estructura AccessToken (vc como object vs string) | ALTA | AC-09 snapshot test confirma claims raíz indistinguibles |
| 2 | SchemaProfile.wrapVcInAccessToken inconsistencia | MEDIA | Task 26 regression: cada profile valida valor correcto |
| 3 | Allowlist rompe si depende de credential_configuration_id | MEDIA | EC-05 test: allowlist funciona igual legacy + bumped |
| 4 | @context + type[] conflictivos (una v1.1, otro bumped) | MEDIA | Dispatcher prioriza type[], loguea WARN + métrica |
| 5 | TenantConfigPort caché stale durante restart DB | MEDIA | ES-06: stale-while-error manejado por port existente |
| 6 | Reader lanza excepción inesperada | BAJA | ES-08: try/catch (RuntimeException) en dispatcher → 400 |

---

## 📈 Métricas de éxito / Observabilidad

### Métricas obligatorias

```
dome_verifier_dispatcher_total{
  tenant="dome",
  format="legacy|bumped|unknown",
  decision="permit|deny",
  reason="by_type|by_context|legacy_sunset_closed|bumped_disabled|unclassifiable|..."
}

dome_verifier_dispatcher_duration_ms{
  tenant="dome",
  format="legacy|bumped"
}

dome_verifier_legacy_replay_after_sunset_total{
  tenant="dome"
}  // Alerta P2 si > 0 después cierre del flag
```

### Métricas opcionales (observabilidad)
```
dome_verifier_wrap_vc_applied_total{tenant,format}
dome_verifier_context_type_mismatch_total{tenant}
```

---

## 📝 Plan de tareas (alto nivel)

1. **Modelos dominio** (tasks 1–4): DispatchDecision, DispatchRule, enums, ports
2. **Configuración Spring** (task 5): DispatchProperties, defaults, caché
3. **Dispatcher + Readers** (tasks 6–8): Core logic dual-format
4. **Builder + Excepciones** (tasks 9, 13): AccessTokenBuilder, RFC 9457 mapping
5. **Workflows** (tasks 10–12): Integración minimal en flujos existentes
6. **Métricas** (task 14): Micrometer instrumentation
7. **Fixtures** (task 15): Credenciales de prueba v1.1 + v2.0
8. **Tests** (tasks 16–26): Unitarios, integration, regression

---

## ✅ Checklist pre-implementación

- [ ] Confirmar fuente de `SchemaProfile.wrapVcInAccessToken` (JSON vs BD vs hardcode)
- [ ] Definir la abstracción concreta para flags por tenant: nuevo port/provider o extensión de una capa existente
- [ ] Revisar `CredentialTypeResolver` API exacta
- [ ] Confirmar `LocalSchemaProfileRegistry` soporta leer `wrapVcInAccessToken` del JSON
- [ ] Verificar que allowlist NO depende de credential_configuration_id (si depende, EC-05 fallará)
- [ ] Confirmar que `SchemaProfile` bumped declara `grant_eligibility: ["client_credentials"]`
- [ ] Revisar RFC 9457 HTTP status mapping esperado (410, 503, 400)
- [ ] Confirmar que `VpService.extractCredentialFromVerifiablePresentationAsJsonNode()` es la entrada correcta

---

## 📚 Referencias

- **Especificaciones:** 
  - [`user-story.md`](user-story.md) — propuesta funcional
  - [`acceptance-criteria.md`](acceptance-criteria.md) — GWT canónicos
  - [`technical-design.md`](technical-design.md) — detalles arquitectónicos
  - [`tasks.md`](tasks.md) — breakdown de tareas
  
- **Feature parent:** [`../specs/architecture.md`](../specs/architecture.md) — AD-3, §3.3, §6.2, §9.4
- **Normative:** OID4VP 1.0, W3C VCDM v1.1, W3C VCDM v2.0, RFC 9457

---

## 🎯 Recomendación final

**La arquitectura propuesta es sólida y escalable.** La separación entre dispatcher (discriminador determinista), readers (extractores per-formato) y builder (constructor de token) es limpia y testeable. 

**Puntos clave para evitar sorpresas:**
1. Confirmar SchemaProfile.wrapVcInAccessToken source antes de task 5
2. Asegurar allowlist test (EC-05) antes de mergear
3. Snapshot test AccessToken (AC-09) para detectar cambios estructura temprano
4. Métricas desde el primer deploy (visibility post-sunset es crítica)

**Go/No-Go:**
- Si los 3 puntos bloqueantes se clarifican ✅, la implementación puede empezar inmediatamente
- Estimación: ~8-10 sprints para tasks 1–26 + closing

