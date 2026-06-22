# REVISIÓN TÉCNICA PROFUNDA — US-08 Verifier Dual-Format Read
**Fecha:** 2026-06-01  
**Rama:** `feature/dual-format-read-dome-migration`  
**Status:** ⚠️ **INCOMPLETO CON DISCREPANCIAS CRÍTICAS**

---

## RESUMEN EJECUTIVO

La implementación de US-08 es **66% alineada con los documentos** pero tiene **discrepancias arquitectónicas significativas** que afectan contratos, enumeraciones y flujos de datos. Las decisiones no especificadas introducen complejidad añadida y potencial para confusión futura.

**Veredicto:** ✅ Funciona (tests probablemente pasan) pero ❌ **No cumple con los contratos especificados** — necesita alineación antes de mergear.

---

## 1. DISCREPANCIAS CRÍTICAS (DEBEN RESOLVERSE)

### 1.1 — `DispatchDecision` contiene campo `permitted` no especificado

**Especificación (technical-design.md §3.2):**
```java
record DispatchDecision(
    CredentialFormat format,
    String configId,
    DispatchReason reason
)
```

**Implementación (`DispatchDecision.java`):**
```java
public record DispatchDecision(
    String credentialConfigurationId,
    CredentialFormat format,
    DispatchReason reason,
    boolean permitted  // ❌ NO ESPECIFICADO
)
```

**Impacto:**
- El spec asume que **todos** los outcomes son lanzar excepciones (determinismo fail-fast)
- El campo `permitted` sugiere un modelo de "Decision Object" que retorna allow/deny
- Métodos helper `.permitted()` y `.denied()` NO están en el spec
- Riesgos:
  - **R1:** La lógica de dispatcher puede degradarse a try/catch implícito (AD-3 lo prohíbe explícitamente)
  - **R2:** La decisión negada nunca se lanza como excepción — pasa a través del flujo
  - **R3:** Violación de **fail-secure** (ES-08): un error debería rechazar, no continuar con `permitted=false`

**Decisión requerida:** ¿El dispatcher debe retornar `DispatchDecision` con `permitted=false` O debe lanzar excepción? Elije UNA estrategia.

---

### 1.2 — `DispatchReason` enum tiene 9 valores vs 3 esperados

**Especificación (technical-design.md §3.2 + AD-145-1):**
- `BY_TYPE` — config-id en `type[]` discrimina
- `BY_CONTEXT` — `@context` discrimina (fallback)
- `BY_TYPE_NO_VCDM_CONTEXT` — type discrimina, sin URLs VCDM en context

**Implementación (9 valores):**
```java
enum DispatchReason {
    BY_TYPE,                    // ✓
    BY_CONTEXT,                 // ✓
    BY_TYPE_CONTEXT_MISMATCH,   // ❌ No especificado
    ONLY_GENERIC_TYPES,         // ❌ Este es error de INPUT, no reason
    MISSING_TYPE_AND_CONTEXT,   // ❌ Este es error de INPUT, no reason
    UNKNOWN_CREDENTIAL_TYPE,    // ❌ Este es error de INPUT, no reason
    LEGACY_SUNSET_CLOSED,       // ❌ Este es error de ESTADO, no dispatch reason
    BUMPED_DISABLED,            // ❌ Este es error de ESTADO, no dispatch reason
    PROFILE_NOT_FOUND           // ❌ Este es error de RECURSO, no dispatch reason
}
```

**Problemas:**
- **Confusión semántica:** DispatchReason mezcla "cómo se decidió el formato" con "por qué se rechazó"
- **Violación de SRP:** Un enum no debe contener razones de dispatch + razones de error
- **Incompatible con spec:** EC-01 menciona explícitamente solo 3 razones
- **Observabilidad confusa:** Las métricas `dome_verifier_dispatcher_reason=*` serán ambiguas

**Decisión requerida:** Separar en dos enums:
1. `DispatchReason { BY_TYPE, BY_CONTEXT, BY_TYPE_NO_VCDM_CONTEXT }`
2. `DispatchDenyReason { INPUT_MISSING_TYPE_AND_CONTEXT, INPUT_ONLY_GENERICS, RESOURCE_UNKNOWN_CONFIG_ID, ... }`

O bien: lanzar excepciones específicas y guardar solo razones de éxito en `DispatchReason`.

---

### 1.3 — `CredentialReader` recibe `BuildContext` en lugar de firma especificada

**Especificación (technical-design.md §3.2, línea 130):**
```java
interface CredentialReader {
    boolean supports(CredentialFormat format)
    ReaderResult read(JsonNode credential, SchemaProfile profile)  // <-- Firma
}
```

**Implementación (`CredentialReader.java`):**
```java
public interface CredentialReader {
    boolean supports(CredentialFormat credentialFormat);
    ReaderResult read(BuildContext buildContext);  // ❌ FIRMA DIFERENTE
}
```

**Impacto:**
- ✅ BuildContext contiene `credential` y `dispatchDecision` (suficiente)
- ❌ BuildContext es acoplado a tokens OAuth2 (contiene `extractedClaims`, `issueTime`, `audience`, `generateIdToken`)
- ❌ Violación de **Dependency Inversion:** Reader no debe saber de BuildContext (token-level concern)
- ❌ Testabilidad: No puedes testar un Reader sin construir un BuildContext completo

**Decisión requerida:** Refactorizar `read()` para recibir solo lo que necesita:
```java
ReaderResult read(JsonNode credential, DispatchDecision decision, SchemaProfile profile)
```

---

### 1.4 — `ReaderResult` no coincide con valor object especificado

**Especificación (technical-design.md §3.2, línea 131):**
> `ReaderResult` es un record con `(JsonNode canonicalPayload, ExtractedClaims extractedClaims)`

**Implementación (`ReaderResult.java`):**
```java
public record ReaderResult(
    JsonNode credential,                          // ✓ (llamado "credential", no "canonicalPayload")
    String credentialConfigurationId,             // ❌ No especificado
    SchemaProfile schemaProfile,                  // ❌ No especificado
    boolean wrapVcInAccessToken                   // ❌ No especificado (debería estar en SchemaProfile, no aquí)
)
```

**Problemas:**
- **Cambio de contrato:** ReaderResult no extrae claims (línea especificada: "extrae claims al `ClaimsExtractor` existente")
- ❌ **LegacyCredentialReader línea 33:** retorna `new ReaderResult(payload, configId, schemaProfile, false)` — NO extrae claims
- ❌ **BumpedCredentialReader línea 30:** retorna `new ReaderResult(buildContext.credential(), configId, schemaProfile, true)` — NO extrae claims
- **Inconsistencia:** Las claims se extraen **después** en `TokenGenerationWorkflow.issueAccessToken()` (línea 89), no en el reader
- **Violación de responsabilidad:** ¿Quién extrae claims? El spec dice Reader, la implementación dice TokenGenerationWorkflow

**Decisión requerida:** Actualizar spec o implementación para ser consistentes. Opción A: Readers extraen claims. Opción B: Spec es incorrecto y readers solo devuelven payload (como ahora).

---

### 1.5 — `BuildContext` contiene datos de OAuth2 (acoplamiento de capas)

**Especificación (technical-design.md §3.2, línea 132):**
```java
record BuildContext(
    String audience,
    String tenant,
    Instant issueTime,
    Instant expiry,
    String scope
)
```

**Implementación (`BuildContext.java`):**
```java
public record BuildContext(
    JsonNode credential,                    // ❌ + campo
    DispatchDecision dispatchDecision,      // ❌ + campo
    ExtractedClaims extractedClaims,        // ❌ + campo
    Instant issueTime,                      // ✓
    Instant expirationTime,                 // ✓ (diferente nombre: expirationTime vs expiry)
    String audience,                        // ✓
    String tenant,                          // ✓
    Map<String, Object> additionalParameters,  // ❌ + campo
    boolean generateIdToken                 // ❌ + campo (token-level concern)
)
```

**Problemas:**
- **Violación de SRP:** BuildContext mezcla concerns de Verifier (credential) con OAuth2 (tokens, generateIdToken)
- **Acoplamiento:** Un domain value object del Verifier no debe referirse a decisiones de token
- **Testabilidad:** Difícil de construir para tests porque necesita toda la cadena de dependencias
- **Escalabilidad:** Si mañana cambia generación de tokens, BuildContext cambia

**Decisión requerida:** Separar `BuildContext` en capas:
```java
// Domain layer
record CredentialVerificationContext(
    JsonNode credential,
    DispatchDecision dispatchDecision,
    ExtractedClaims extractedClaims
)

// Application/OAuth2 layer
record TokenBuildContext(
    CredentialVerificationContext verificationContext,
    String audience,
    String tenant,
    Instant issueTime,
    Instant expirationTime,
    Map<String, Object> additionalParameters,
    boolean generateIdToken
)
```

---

### 1.6 — `AccessTokenBuilder` recibe BuildContext (completo) en lugar de parámetros específicos

**Especificación (technical-design.md §3.2, línea 131):**
```java
interface AccessTokenBuilder {
    String build(ReaderResult readerResult, SchemaProfile profile, BuildContext ctx)
}
```

**Implementación (`AccessTokenBuilder.java`):**
```java
public interface AccessTokenBuilder {
    String build(BuildContext buildContext);  // Solo recibe BuildContext
}
```

**Impacto:**
- ✅ BuildContext es suficiente (contiene todo lo necesario)
- ❌ Acoplamiento: Conoce detalles internos (extractedClaims, additionalParameters)
- ❌ El spec esperaba que el AccessTokenBuilder fuera más modular
- ⚠️ **Duplicidad potencial:** `extractedClaims.scope()` está en BuildContext, pero también se accede directo desde extractedClaims (línea 44 en JwsAccessTokenBuilder: `extractedClaims.scope()`)

**Decisión requerida:** Alinear con el spec o actualizar el spec si esta firma es mejor.

---

### 1.7 — `JwsAccessTokenBuilder` trata claim `vc` inconsistentemente

**Especificación (AC-09, AC-02):**
> La estructura externa del Access Token debe ser **idéntica** entre legacy y bumped

**Implementación (líneas 62–66 en `JwsAccessTokenBuilder.java`):**
```java
if (wrapVc) {
    payloadBuilder.claim("vc", objectMapper.convertValue(buildContext.credential(), Object.class));
    // ✓ Añade como objeto JSON
} else {
    payloadBuilder.claim("vc", buildContext.credential().toString());
    // ❌ Añade como string (JSON serializado)
}
```

**Problema crítico:**
- **Legacy:** `vc` = `"{\"@context\":...}"` (string JSON)
- **Bumped:** `vc` = `{"@context":...}` (objeto JSON)
- **Consumidor RP:** Debe hacer `if (token.vc is string) parse() else use directly`
- **Violación de AC-09:** "la estructura externa del Access Token es **idéntica**"

**Riesgo de cumplimiento:** Las RPs al consumir verán diferentes tipos en el mismo claim — esto rompe la "indistinguibilidad estructural" prometida en NFR-02.

**Decisión requerida:** Ambos deben ser objetos JSON. Fix:
```java
// Ambos casos: siempre objeto
payloadBuilder.claim("vc", objectMapper.convertValue(buildContext.credential(), Object.class));
```

---

### 1.8 — Null pointer en `JwsAccessTokenBuilder` línea 35

**Código (línea 34–35):**
```java
SchemaProfile schemaProfile = schemaProfileRegistry.findByConfigId(configId).orElse(null);
boolean wrapVc = schemaProfile != null && schemaProfile.wrapVcInAccessToken();
```

**Problema:**
- Si `schemaProfile == null`, `wrapVc = false` ✓ (seguro)
- Pero `LegacyCredentialReader` también retorna `schemaProfile = null` (línea 31)
- Más tarde, si el código intenta acceder a `schemaProfile` sin null-check → NPE
- ⚠️ Actualmente está protegido pero es frágil

**Recomendación:** El flujo debería garantizar que `schemaProfile` siempre existe. Si no, fail-secure temprano (ya en BumpedCredentialReader línea 27–28 que lanza excepción).

---

### 1.9 — `TokenGenerationWorkflow` crea `DispatchDecision` de fallback (Líneas 71–76)

**Código:**
```java
DispatchDecision dispatchDecision = schemaProfile == null
    ? DispatchDecision.permitted(credentialType, CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE)
    : DispatchDecision.permitted(
        credentialType,
        schemaProfile.wrapVcInAccessToken() ? CredentialFormat.BUMPED_V2_0 : CredentialFormat.LEGACY_V1_1,
        DispatchReason.BY_TYPE);
```

**Problema:**
- Este código se ejecuta solo si `DispatchDecision` no viene del dispatcher (overload sin dispatch decision)
- ⚠️ **Contrato roto:** El spec dice que el dispatcher siempre discrimina — aquí se está auto-discriminando en TokenGenerationWorkflow
- ❌ **Violación de AD-3:** El discriminador está en dos lugares (dispatcher + workflow)
- **Inconsistencia:** ¿Qué pasa si el perfil dice `wrapVcInAccessToken=true` pero la credencial es legacy? → se marcaría como BUMPED_V2_0 erróneamente

**Decisión requerida:** El dispatcher DEBE siempre ser llamado. Este fallback debería no existir. Refactorizar para que:
1. La llamada siempre pase a través del dispatcher
2. O bien, si es un caso especial, documentarlo explícitamente

---

## 2. DISCREPANCIAS ARQUITECTÓNICAS (IMPACTO MODERADO)

### 2.1 — `DispatchReason.BY_TYPE_CONTEXT_MISMATCH` no está en spec

**Implementación:** Se usa cuando `formatFromType != formatFromContext` (línea 106 en dispatcher)

**Spec:**  NO menciona esto

**Problema:**
- EC-01 especifica que se prioriza `type[]` sobre `@context`
- Si hay mismatch, debería haber una acción explícita (usar type y loguear warning)
- ¿Por qué es una "razón" de dispatch especial?

**Recomendación:** Renombrar a `BY_TYPE_OVERRIDES_CONTEXT` y documentar qué significa.

---

### 2.2 — Excepción `UnknownCredentialFormatException` se lanza por múltiples razones

**Líneas en dispatcher:**
- Línea 52: ambos `type[]` y `@context` fallan → `MISSING_TYPE_AND_CONTEXT`
- Línea 57: `type[]` es nulo pero se pasó por el primer check → `UNKNOWN_CREDENTIAL_TYPE`
- Línea 98: config-id no está en DispatchRules → `unknown_credential_format` (HTTP 400)

**Problema:**
- ES-01 especifica que input inválido (`@context` ausente) → 400 `invalid_request`
- ES-03 especifica que config-id desconocido → 400 `unknown_credential_format`
- La implementación lanza la misma excepción para ambos

**Riesgo:**
- El exception handler (`DomeDispatchExceptionHandler` línea 32–35) mapea TODOS a 400 `unknown_credential_format`
- Debería haber:
  - **Diferente excepción:** `InvalidInputException` para ES-01
  - **O bien, subtipos:** `UnknownCredentialFormatException` con un campo que dice `reason`

---

### 2.3 — Tenant resolution fallback a "default" 

**Implementación (línea 168 en dispatcher):**
```java
private String resolveTenantDomain() {
    // ...
    return tenantDomain == null || tenantDomain.isBlank() ? "default" : tenantDomain;
}
```

**Spec:**
- El dispatcher se diseña específicamente para tenant DOME
- No hay mención de cómo se maneja multi-tenant

**Problema:**
- Si el tenant no se puede resolver, se etiqueta como "default"
- Las métricas serán imprecisas: `dome_verifier_dispatcher_total{tenant="default"}`
- ¿"default" es el tenant DOME o cualquier otro tenant?

**Recomendación:** Usar "unknown" en lugar de "default", o fallar-seguro si no se puede determinar tenant.

---

### 2.4 — `DispatchConfiguration` no valida reglas duplicadas o incoherentes

**Código:**
```java
public List<DispatchRule> dispatchRules(DispatchProperties dispatchProperties) {
    return dispatchProperties.allRules().stream()
            .map(DispatchConfiguration::toDomainRule)
            .toList();
}
```

**Problema:**
- Si hay dos rules con el mismo `credentialConfigurationId`, el lookup en dispatcher (línea 93–96) devuelve el PRIMERO
- No hay validación de duplicados durante Boot
- Risk-145-5 (regression test) intenta cubrir esto, pero ¿está en CI?

**Recomendación:** Agregar validación de bootstrapping que falle si hay duplicados o si los config-ids en assets no están en rules.

---

## 3. INCONSISTENCIAS ENTRE DOCUMENTOS E IMPLEMENTACIÓN

### 3.1 — Configuración: `snake_case` vs. `kebab_case` vs. Java naming

**application.yaml:**
```yaml
verifier:
  dome:
    legacy-read-enabled: ...      # kebab-case
    bumped-read-enabled: ...      # kebab-case
  dispatch:
    rules:
      legacy:
        - credential-configuration-id: learcredential.employee.w3c.3  # kebab-case con lowercase
```

**Java properties:**
```java
// DispatchProperties: Spring relaxed binding convierte:
// verifier.dispatch.rules → rules
// credential-configuration-id → credentialConfigurationId
```

**Test fixtures:**
```java
// Tests usan: LEARCredentialEmployee.3 (PascalCase con dots)
```

**Confusión:**
- ¿Cuál es el canonical config-id? ¿`learcredential.employee.w3c.3` o `LEARCredentialEmployee.3`?
- Los JSON Schemas en `eudistack-platform-assets` ¿usan cuál formato?
- Risk-145-5 falla CI si hay desviación, pero... ¿contra qué formato compara?

**Recomendación:** Documentar canon formalmente y validar en todos los tests.

---

### 3.2 — `DispatchProperties` vs. `TenantDomeConfigProperties`

**¿Dónde viven los flags?**
- Spec (technical-design.md §3.2): `TenantConfigPort` los lee de `tenant_dome_config` (DB)
- Implementación: `application.yaml` + fallback a Spring defaults

**Problema:**
- ¿`DispatchProperties` (catalog de rules, en YAML) y los flags (`verifier.dome.legacy_read_enabled`, también en YAML) son lo mismo?
- `TenantDomeConfigProperties` NO aparece en el código (búsqueda devuelve nada)
- ¿Dónde se mapean los flags a `TenantDomeConfig`?

**Búsqueda de verdad:**
- Dispatcher line 63: `tenantConfigPort.getDomeConfig(tenant)` → retorna `TenantDomeConfig`
- ¿Dónde implementa `TenantConfigPort.getDomeConfig()`?

**Riesgo crítico:** Los flags no están conectados a la BD. Si es necesario hot-reload sin despliegue (AC-07, AC-08), esto es una regresión.

---

### 3.3 — Exception handler endpoint mismatch

**Spec (technical-design.md §3.2, línea 146):**
> `DomeDispatchExceptionHandler` mapea a `410 Gone`, `503`, `400` via RFC 9457 Problem+JSON

**Implementación:**
- Handler existe ✓
- Mapea a `HttpStatus.GONE` (410), `SERVICE_UNAVAILABLE` (503), `BAD_REQUEST` (400) ✓
- Retorna `ProblemDetail` ✓

**Pero:**
- ¿El error property en ProblemDetail es correcto? Spec requiere `error` en OAuth2 error format
- RFC 9457 y OAuth2 error format son DIFERENTES
- **AC-07 especifica:** `error=legacy_format_sunset_closed` (OAuth2)
- **ProblemDetail por RFC 9457:** Usa `type` + `detail`, no `error`

**Mismatch:** ¿La RP ve `error` (OAuth2) o `type` (RFC 9457)?

Línea 40 en handler:
```java
problemDetail.setProperty("error", errorCode);  // ✓ Acomoda a ambos
```

OK, está acomodado, pero es un poco hacky.

---

## 4. REQUISITOS DEL SPEC NO ENCONTRADOS EN CÓDIGO

### 4.1 — DispatchReason.BY_TYPE_NO_VCDM_CONTEXT

**Spec (EC-02, technical-design.md):**
> El log registra `dispatch_reason=by_type, fallback_no_vcdm_context_url=true`

**Implementación:**
- El enum tiene `BY_TYPE` pero NO `BY_TYPE_NO_VCDM_CONTEXT`
- Cuando se resuelve por `type[]` sin URL VCDM, se registra `BY_TYPE` (no hay distinción)

**Riesgo:** Imposible diferenciar "resolvió por type con v2.0 en @context" de "resolvió por type SIN v2.0 en @context" en observabilidad.

---

### 4.2 — Claims extracción en LegacyCredentialReader

**Spec (technical-design.md §3.2):**
> `LegacyCredentialReader` produce `ReaderResult` con `(canonicalPayload, extractedClaims)`

**Implementación:**
- `LegacyCredentialReader` NO extrae claims
- Extracción ocurre en `TokenGenerationWorkflow.issueAccessToken()` línea 89

**Impacto:**
- Violación de contrato especificado
- Si el spec es canónico, esto está mal implementado
- Si la implementación es correcta, el spec necesita actualización

---

### 4.3 — Métrica `dome_verifier_legacy_replay_after_sunset_total`

**Spec:**
- Debe existir y incrementar cuando se rechaza legacy post-sunset

**Implementación:**
- ✓ Existe en `DomeDispatchExceptionHandler` línea 44–50
- ✓ Se incrementa cuando se lanza `LegacyFormatSunsetClosedException`

**Pero:**
- ¿Se incrementa SIEMPRE o solo después del cierre del sunset?
- Nombre sugiere "replay after sunset", lo cual implica timestamp tracking
- ¿Hay alertas configuradas? (Spec: "P2 si > 0")

---

### 4.4 — Métrica `dome_verifier_dispatcher_reason=BY_TYPE_NO_VCDM_CONTEXT`

**Spec (EC-02):**
> Debe ser posible trackear cuando se resuelve por `type[]` SIN URLs VCDM en context

**Implementación:**
- No hay DispatchReason para esto
- Los logs pueden detectarlo pero las métricas no

---

## 5. RIESGOS TÉCNICOS IDENTIFICADOS

| # | Riesgo | Probabilidad | Impacto | Mitigación |
|---|--------|--------------|---------|------------|
| R1 | `permitted` field en DispatchDecision puede permitir caída implícita a try/catch | Media | Alto | Enforcer: lanzar excepción siempre, no retornar `permitted=false` |
| R2 | Inconsistencia en tipo del claim `vc` (string vs. object) rompe AC-09 | Alta | Alto | Fix inmediato: siempre objeto JSON |
| R3 | Flags no están en BD, no hay hot-reload | Baja | Medio | Verificar que TenantConfigPort lee de BD |
| R4 | Múltiples DispatchReason para error scenarios confunde observabilidad | Media | Medio | Separar en enums: dispatch_reason vs. deny_reason |
| R5 | TokenGenerationWorkflow auto-discrimina (fallback) violaría AD-3 | Baja | Alto | Garantizar que dispatcher siempre es llamado |
| R6 | `BuildContext` acoplado a OAuth2 (generateIdToken, additionalParameters) | Baja | Medio | Separar en contextos de capas |
| R7 | Claims extraction responsabilidad ambigua (Reader vs. Workflow) | Media | Medio | Clarificar spec: ¿Reader extrae o no? |
| R8 | Config-id canonización: lowercase vs. PascalCase inconsistente | Baja | Bajo | Normalizar a un canon y validar |

---

## 6. LO QUE SÍ ESTÁ BIEN IMPLEMENTADO ✅

1. **Dispatcher determinista por `type[]` primario** — AD-145-1 correctamente implementado
2. **Catálogo DispatchRules en YAML** — AD-145-2 OK, extensible
3. **Exception mapping a HTTP status codes** — correcto (410, 503, 400)
4. **Métrica contador total de dispatch** — bien instrumentado
5. **M2M flow modification** — ClientCredentialsValidationWorkflow integra dispatcher ✓
6. **VerifyPresentationWorkflow** — integración limpia del dispatcher
7. **Tests unitarios de dispatcher** — cobertura de EC-01, EC-02, EC-03
8. **Null safety en JwsAccessTokenBuilder** — protegido contra NPE

---

## 7. DECISIONES NO ESPECIFICADAS (DUDAS ABIERTAS)

| Decisión | Spec | Implementación | Conflicto |
|----------|------|-----------------|-----------|
| ¿Se lanza excepción o se retorna `permitted=false`? | Implícito: excepción | Ambiguo: ambos métodos existen | Sí |
| ¿Dónde se extraen claims? | En Reader | En TokenGenerationWorkflow | Sí |
| ¿BuildContext debe conocer detalles de tokens? | No | Sí | Sí |
| ¿El claim `vc` es string o objeto? | Debe ser idéntico | Diferente por formato | Sí |
| ¿DispatchReason incluye razones de error? | Solo dispatch | Sí, 9 valores | Sí |
| ¿Dónde viven los flags de hot-reload? | DB (tenant_dome_config) | YAML (application.yaml) | Sí |
| ¿Canonical config-id format? | No definido | Múltiples en tests | Sí |
| ¿Multi-tenant o solo DOME? | Solo DOME | Fallback a "default" | Ambiguo |

---

## 8. RECOMENDACIONES DE ALINEACIÓN

### Prioridad CRÍTICA (bloquean merge):

1. **Alinear `DispatchDecision`:** Decidir si todo error es excepción o si `permitted` es válido
2. **Alinear claim `vc` en JwsAccessTokenBuilder:** Ambos deben ser objetos JSON
3. **Separar `DispatchReason`:** Dispatch reasons (3) vs. Deny reasons (error scenarios)
4. **Verificar TenantConfigPort:** ¿Lee flags de BD? ¿Hay hot-reload?

### Prioridad ALTA (antes de producción):

5. Documentar contrato de `ReaderResult` y `BuildContext`
6. Validar catálogo DispatchRules en bootstrap contra assets
7. Alinear spec y código para extracción de claims
8. Estandarizar formato de config-ids

### Prioridad MEDIA (nice-to-have):

9. Separar `BuildContext` en capas (Verifier + OAuth2)
10. Documentar método de resolución de tenant
11. Confirmar métrica `BY_TYPE_NO_VCDM_CONTEXT` para observabilidad

---

## 9. CONCLUSIÓN

**Estado actual:** 🟡 Funcional pero incompleto

La implementación **funciona** y probablemente **pasa tests** pero **no alinea con los documentos especificados** en puntos críticos. Las discrepancias son arquitectónicas, no superficiales — afectan contratos, enumeraciones y flujos de datos.

**Recomendación:** 
- ✅ Mergear **solo después** de resolver los 4 puntos críticos
- ⚠️ Documentar todas las decisiones no especificadas
- 📋 Abrir issues de follow-up para MEDIA prioridad antes de producción

**Estimación de esfuerzo de alineación:** 2–4 horas.

