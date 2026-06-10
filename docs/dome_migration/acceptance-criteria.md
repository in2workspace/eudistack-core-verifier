# EUDISTACK-145: US-08 Verifier dual-format read (legacy + bumpeado) — Acceptance Criteria

> **Plantilla canónica de los criterios de aceptación de una Story** (sub-SRS por Story según ISO/IEC/IEEE 29148:2018 §9.4 + formato Given/When/Then de Scrum/BDD).
>
> Las ACs viven **una sola vez** en este documento. El `user-stories.md` del Epic solo lleva título + outcome. La trazabilidad inversa apunta a los FRs del `srs.md` del Epic.
>
> **Autor:** Product Owner + Software Architect (Architect aporta NFRs técnicos y edge cases derivados de la arquitectura).
> **Validadores:** PO · Software Architect.

| Field | Value |
|-------|-------|
| Status | **Draft** |
| Lock status | **Editable** |
| Date | 2026-05-19 |
| Story | EUDISTACK-145 |
| Epic | EUDISTACK-12 |
| SRS ref | [`../specs/srs.md`](../specs/srs.md) |
| User Story ref | [`user-story.md`](user-story.md) |

> **Lock status rules:**
>
> - `Editable` — Story en estado `Ready`. PO + Architect pueden modificar.
> - `Locked (In Sprint)` — Story en estado `In Sprint`. **Ningún agente puede modificar este documento.** Cualquier delta detectado durante `/implement` o `/code-review` debe documentarse en `spec-deltas.md` y escalar al PO/Architect.

---

> **Naturaleza del documento — Acceptance Criteria = contrato de "Done" de la Story.**
>
> **Permitido aquí:** ACs G/W/T · edge cases · error scenarios · Story-specific NFRs · test matrix · trazabilidad inversa.
> **Prohibido aquí:** diseño técnico (clases, secuencias, queries) — vive en `technical-design.md`.

---

## 1. Acceptance criteria (Given/When/Then)

> Una AC por escenario observable. Numeración estable. Cada AC mapea a ≥ 1 FR del SRS del Epic.

### AC-01 — Happy path lectura legacy (RP allowlist, Employee `.3`)

**Trace:** FR-04 (SRS §3.1) · NFR-02 (SRS §3.2)

```gherkin
Given el Verifier del tenant DOME desplegado con `verifier.dome.legacy_read.enabled=true`
  And `verifier.dome.bumped_read.enabled=true`
  And una Relying Party DOME pre-existente cuyo client_id está en el allowlist del Verifier
  And una credencial DOME legacy `LEARCredentialEmployee.3` firmada por la clave DOME, en formato W3C VCDM v1.1 (JWT con wrap `vc` ya presente al nivel raíz del payload)
When la RP presenta la credencial al Verifier vía `POST /oauth/token` (grant `urn:ietf:params:oauth:grant-type:vp_token` o equivalente al pre-migración) preservando exactamente la misma secuencia de llamadas que pre-migración
Then el Verifier responde `200 OK`
  And el cuerpo de respuesta contiene un Access Token firmado por la clave del Verifier DOME
  And al decodificar el Access Token, el claim `vc` contiene la credencial legacy `LEARCredentialEmployee.3` tal como vino (no se aplica wrap adicional — la credencial ya lo trae)
  And el campo `credential_type` del Access Token vale `LEARCredentialEmployee.3`
  And el contador `dome_verifier_dispatcher_total{tenant="dome", format="legacy", decision="permit"}` se incrementa en 1
  And el log de auditoría registra `audit.dome.verifier_dispatch` con `format=legacy, configId=LEARCredentialEmployee.3, outcome=permit`
```

### AC-02 — Happy path lectura bumpeada (RP allowlist, Employee `.4` VCDM v2.0)

**Trace:** FR-04 (SRS §3.1) · FR-06a (SRS §3.1) · NFR-02 (SRS §3.2)

```gherkin
Given el Verifier del tenant DOME desplegado con `verifier.dome.bumped_read.enabled=true`
  And la misma Relying Party del AC-01 sin haber modificado su integración
  And una credencial DOME bumpeada `LEARCredentialEmployee.4` firmada por la clave DOME, en formato W3C VCDM v2.0 canónico (JWT cuyo payload contiene los claims VCDM v2.0 al nivel raíz, sin envoltura `vc` — FR-06b en Issuer ya garantiza esto)
When la RP presenta la credencial al Verifier vía `POST /oauth/token`
Then el Verifier responde `200 OK`
  And el Access Token devuelto contiene el claim `vc` cuyo valor es la credencial `LEARCredentialEmployee.4` canónica (FR-06a: wrap aplicado por el Verifier al construir el Access Token)
  And el campo `credential_type` del Access Token vale `LEARCredentialEmployee.4`
  And la **estructura externa** del Access Token (claims raíz, ubicación de `vc`, presencia de `credential_type`) es **idéntica** a la del AC-01 — la RP no necesita distinguir entre legacy y bumped
  And el contador `dome_verifier_dispatcher_total{tenant="dome", format="bumped", decision="permit"}` se incrementa en 1
  And el log de auditoría registra `format=bumped, configId=LEARCredentialEmployee.4, outcome=permit`
```

### AC-03 — Cobertura de los tres tipos productivos en variante legacy

**Trace:** FR-04 (SRS §3.1)

```gherkin
Given el Verifier con ambos flags `legacy_read` y `bumped_read` activos
When una RP presenta sucesivamente credenciales legacy `LEARCredentialEmployee.3`, `LEARCredentialMachine.2` y `gx:LabelCredential.1`
Then las tres presentaciones reciben `200 OK` con Access Tokens válidos
  And el dispatcher resuelve correctamente cada credencial al `LegacyCredentialReader` por inspección de `@context` (contiene la URL VCDM v1.1) + `type[]` (contiene el config-id legacy)
  And cada Access Token preserva su credencial original bajo `vc` sin alteración estructural
```

### AC-04 — Cobertura de los tres tipos productivos en variante bumpeada

**Trace:** FR-04 (SRS §3.1) · FR-05 (SRS §3.1) · FR-06a (SRS §3.1)

```gherkin
Given el Verifier con `bumped_read=true`
When una RP presenta sucesivamente credenciales bumpeadas `LEARCredentialEmployee.4`, `LEARCredentialMachine.3` y `gx:LabelCredential.2`
Then las tres presentaciones reciben `200 OK` con Access Tokens válidos
  And el dispatcher resuelve cada credencial al `BumpedCredentialReader` por inspección de `@context` (contiene la URL VCDM v2.0 `https://www.w3.org/ns/credentials/v2`) + `type[]`
  And el `AccessTokenBuilder` aplica el wrap `vc` sólo a estas credenciales (FR-06a) y NO al Issuer (FR-06b lo prohíbe en emisión)
```

### AC-05 — Máquina sin registro (M2M client_credentials) con credencial Machine legacy

**Trace:** FR-04 (SRS §3.1) · NFR-02 (SRS §3.2)

```gherkin
Given el Verifier con `legacy_read=true` y `bumped_read=true`
  And una máquina sin registro previo en el allowlist (admisión preservada del pre-migración)
  And una credencial `LEARCredentialMachine.2` legacy con `cnf.jwk` ligado a la clave de la máquina
When la máquina inicia un grant `client_credentials` enviando `client_assertion` con `vp_token` embebido (flujo M2M tal como en pre-migración)
Then el Verifier valida el client_assertion JWT y el VP
  And la `grantEligibility` resuelta vía `SchemaProfile` para `LEARCredentialMachine.2` incluye `client_credentials`
  And el Verifier responde `200 OK` con Access Token que contiene la credencial bajo `vc`
  And el comportamiento es funcionalmente indistinguible del pre-migración (códigos, mensajes de error, forma del Access Token) — NFR-02
```

### AC-06 — Máquina sin registro con credencial Machine bumpeada

**Trace:** FR-04 (SRS §3.1) · FR-06a (SRS §3.1)

```gherkin
Given el Verifier con `bumped_read=true`
  And una máquina sin registro presentando `LEARCredentialMachine.3` (VCDM v2.0)
When la máquina inicia un `client_credentials` grant con la credencial bumpeada
Then el Verifier responde `200 OK` con Access Token donde el wrap `vc` lo aplica el `AccessTokenBuilder` (FR-06a)
  And `grantEligibility` para `LEARCredentialMachine.3` incluye `client_credentials`
  And el formato externo del Access Token es indistinguible del AC-05 desde la perspectiva del consumidor
```

### AC-07 — Cierre del sunset legacy (flag OFF por configuración, sin redeploy)

**Trace:** FR-04 (SRS §3.1, sunset 6–12m) · NFR-04 (SRS §3.2)

```gherkin
Given el Verifier en producción con `verifier.dome.legacy_read.enabled=true` durante el sunset
  And `verifier.dome.bumped_read.enabled=true`
When el Operador del tenant EUDIStack actualiza `tenant_dome_config` poniendo `verifier.dome.legacy_read.enabled=false` mediante configuración (sin desplegar código nuevo)
  And la caché de configuración del Verifier refresca dentro de su TTL (≤ 60s, bounded)
  And una RP intenta verificar una credencial legacy `LEARCredentialEmployee.3` tras el refresh
Then el Verifier responde `410 Gone` con un error auditable cuyo `error` es `legacy_format_sunset_closed`
  And el contador `dome_verifier_legacy_replay_after_sunset_total{tenant="dome"}` se incrementa en 1
  And el log de auditoría registra `format=legacy, configId=LEARCredentialEmployee.3, outcome=deny, reason=sunset_closed`
  And una RP que en la misma ventana verifica una credencial bumpeada `LEARCredentialEmployee.4` sigue recibiendo `200 OK`
```

### AC-08 — Defaults de los flags al desplegar la Story

**Trace:** FR-04 (SRS §3.1) · architecture.md §9.4

```gherkin
Given el código de esta Story mergeado a `main` y desplegado en STG/PROD sin que el comité de cutover haya tocado configuración aún
When se inspecciona la configuración efectiva del Verifier del tenant `dome`
Then `verifier.dome.bumped_read.enabled` vale `true` por defecto (el Verifier ya puede leer bumped desde el despliegue)
  And `verifier.dome.legacy_read.enabled` vale `true` por defecto durante el sunset
  And ambos flags son leídos desde `tenant_dome_config` por `TenantConfigPort` con caché bounded (TTL ≤ 60s)
  And el cambio en caliente de cualquiera de los dos flags surte efecto sin reinicio del servicio
```

### AC-09 — Indistinguibilidad estructural Access Token legacy vs bumpeado

**Trace:** NFR-02 (SRS §3.2) · FR-06a (SRS §3.1)

```gherkin
Given dos credenciales del mismo holder, una `LEARCredentialEmployee.3` legacy y otra `LEARCredentialEmployee.4` bumpeada (mismos claims funcionales)
When la RP presenta cada una al Verifier y compara los Access Tokens devueltos
Then ambos Access Tokens tienen el mismo conjunto de claims raíz (`iss`, `aud`, `sub`, `jti`, `iat`, `exp`, `scope`, `credential_type`, `tenant`, `vc`)
  And el contenido del claim `vc` es la credencial completa firmada en su formato nativo (v1.1 wrappeada-en-credencial · v2.0 wrappeada-por-Verifier)
  And la RP puede consumir `accessToken.claims["vc"]` con el mismo código sin necesidad de ramificar por versión VCDM
```

### AC-10 — Activación independiente de los dos flags (`bumped_read` ON, `legacy_read` OFF)

**Trace:** FR-04 (SRS §3.1) · architecture.md §9.4

```gherkin
Given el Verifier con `verifier.dome.bumped_read.enabled=true` y `verifier.dome.legacy_read.enabled=false`
When una RP presenta una credencial bumpeada `.4/.3/.2`
Then el Verifier responde `200 OK` con Access Token
When una RP presenta una credencial legacy `.3/.2/.1`
Then el Verifier responde `410 Gone` con `error=legacy_format_sunset_closed`
  And el dispatcher NO intenta parsing optimista — la decisión es determinista por `@context` + `type[]` antes de invocar reader (AD-3)
```

---

## 2. Edge cases

### EC-01 — Credencial con `@context` que contiene tanto VCDM v1.1 como v2.0 (mezcla)

**Trace:** FR-04 (extiende)

```gherkin
Given una credencial con `@context = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/ns/credentials/v2", "https://dome-marketplace.eu/.well-known/contexts/employee-v4"]`
  And `type = ["VerifiableCredential", "LEARCredentialEmployee.4"]`
When el dispatcher inspecciona la credencial
Then la decisión se basa **primero en `type[]`**: si contiene un config-id de la familia bumpeada (`.4/.3/.2`) → `BumpedCredentialReader`; si contiene legacy (`.3/.2/.1`) → `LegacyCredentialReader`
  And si `type[]` no es discriminante, se aplica la URL canónica VCDM **más reciente** del `@context` (v2.0 prevalece sobre v1.1)
  And la decisión queda registrada en log con `dispatch_reason={"by_type"|"by_context"}` para trazabilidad
```

### EC-02 — `@context` que NO contiene ninguna URL canónica VCDM conocida

**Trace:** FR-04 (extiende)

```gherkin
Given una credencial con `@context = ["https://dome-marketplace.eu/.well-known/contexts/custom-only"]`
  And `type = ["VerifiableCredential", "LEARCredentialEmployee.4"]`
When el dispatcher inspecciona la credencial
Then la decisión se basa en `type[]` (cae en `BumpedCredentialReader` por `.4`)
  And el log registra `dispatch_reason=by_type, fallback_no_vcdm_context_url=true` (visible para futura depuración pero no afecta al outcome)
```

### EC-03 — `type[]` con orden no canónico (genéricos al final)

**Trace:** FR-04 (extiende)

```gherkin
Given una credencial con `type = ["LEARCredentialEmployee.3", "VerifiableCredential"]` (orden invertido vs habitual)
When el dispatcher inspecciona la credencial
Then la lógica usa `CredentialTypeResolver.resolveConfigId(...)` que filtra genéricos (`VerifiableCredential`, `VerifiableAttestation`) y devuelve el primer no-genérico independientemente del orden
  And el dispatcher resuelve correctamente a `LegacyCredentialReader`
```

### EC-04 — Sunset flag toggleado entre dos peticiones consecutivas

**Trace:** FR-04 (sunset) · architecture.md §9.4

```gherkin
Given el Verifier con `legacy_read=true` y caché TTL de configuración 60s
  And el Operador desactiva el flag a `false` en `tenant_dome_config`
When entre el momento del cambio y el refresh de caché la RP presenta una credencial legacy
Then dentro del TTL la petición se atiende con `200 OK` (comportamiento previsto: caché bounded)
  And tras expirar el TTL, la siguiente petición legacy responde `410 Gone`
  And no se produce inconsistencia de Access Tokens emitidos (todos los emitidos durante la ventana permanecen válidos hasta su `exp`)
```

### EC-05 — Allowlist preserva su semántica pre-migración (Story acceptance, no introduce mecánica nueva)

**Trace:** FR-04 (preservación allowlist)

```gherkin
Given el Verifier con dispatcher dual-format desplegado
  And el mismo provider de allowlist y `ClientRegistryProvider` que en pre-migración
When una RP en allowlist presenta una credencial (legacy o bumpeada)
Then la verificación procede normalmente
When una RP NO en allowlist presenta una credencial
Then el Verifier la rechaza con el mismo código de error que pre-migración (NFR-02 — la Story NO introduce cambios en el componente de allowlist)
```

### EC-06 — Máquina sin registro: schema bumpeado debe declarar `client_credentials` en `grantEligibility`

**Trace:** FR-04 · arquitectura `SchemaProfile.grantEligibility`

```gherkin
Given los JSON Schemas bumpeados `LEARCredentialMachine.3` cargados desde `eudistack-platform-assets` vía `SchemaProfileRegistry`
When el Verifier inspecciona el `SchemaProfile` resuelto
Then `grantEligibility` incluye `client_credentials` (preservando paridad con `LEARCredentialMachine.2`)
  And el `ClientCredentialsValidationWorkflow` admite la presentación bumpeada sin cambios de código (la mecánica ya consulta `SchemaProfile.grantEligibility()`)
```

### EC-07 — Schema bumpeado emite registro de profile que el Verifier todavía no tiene cargado

**Trace:** FR-04 (extiende) · architecture.md M-4

```gherkin
Given una credencial bumpeada cuyo `credential_configuration_id` no tiene `SchemaProfile` cargado en el Verifier (el seed M-4 aún no ha corrido)
When el dispatcher resuelve la credencial al `BumpedCredentialReader`
  And el reader intenta resolver `SchemaProfile` para construir el Access Token
Then el Verifier responde `400 Bad Request` con `error=invalid_request, error_description="No schema profile for: LEARCredentialEmployee.4"`
  And el log registra la causa para que el Operador detecte que falta el seed
  And el dispatcher NO degrada a `LegacyCredentialReader` (fail-secure — no se acepta una credencial que no se puede validar)
```

---

## 3. Error scenarios

> Cubre las 5 categorías canónicas: input inválido, recurso ausente, conflicto de estado, fallo de dependencia externa, timeout.

### ES-01 — Input inválido: `@context` ausente o no es array (input inválido)

**Trace:** FR-04 (error path) · NFR-02

```gherkin
Given una credencial sin campo `@context` o con `@context` que no es array
When la RP la presenta al Verifier
Then el Verifier responde `400 Bad Request` con `error=invalid_request, error_description="'@context' field is missing or is not an array"`
  And el contador `dome_verifier_dispatcher_total{decision="deny"}` se incrementa con etiqueta `reason=missing_context`
  And el log de auditoría registra el rechazo SIN incluir el cuerpo de la credencial en claro (NFR-06 — confidencialidad PII)
```

### ES-02 — Input inválido: `type[]` solo contiene genéricos (`VerifiableCredential`) sin config-id

**Trace:** FR-04 (error path)

```gherkin
Given una credencial con `type = ["VerifiableCredential"]` exclusivamente (sin un config-id discriminante)
  And tampoco contiene un claim `vct` (SD-JWT VC)
When la RP la presenta al Verifier
Then el Verifier responde `400 Bad Request` con `error=invalid_request, error_description="Cannot resolve credential type: no 'type' array or 'vct' claim found"`
  And el dispatcher rechaza fail-secure: NO intenta probar readers en cascada
```

### ES-03 — Recurso ausente: `credential_configuration_id` desconocido (formato no clasificable)

**Trace:** FR-04 (error path)

```gherkin
Given una credencial cuyo config-id es `UnknownDomeCredential.1` (no es ni `.3/.2/.1` legacy ni `.4/.3/.2` bumpeado ni cualquier otro `SchemaProfile` cargado)
When la RP la presenta al Verifier
Then el Verifier responde `400 Bad Request` con `error=unknown_credential_format`
  And el dispatcher registra `dispatch_decision=unclassifiable, configId=UnknownDomeCredential.1`
  And NO se aplica ningún reader (fail-secure)
```

### ES-04 — Conflicto de estado: flag `legacy_read=false` y credencial legacy presentada

**Trace:** FR-04 (sunset) · architecture.md §9.4 · AC-07

```gherkin
Given el Verifier con `verifier.dome.legacy_read.enabled=false` (sunset cerrado)
When una RP presenta una credencial `LEARCredentialEmployee.3` legacy
Then el Verifier responde `410 Gone` con `error=legacy_format_sunset_closed, error_description="Legacy credential format is no longer accepted at this tenant"`
  And el contador `dome_verifier_legacy_replay_after_sunset_total{tenant="dome"}` se incrementa en 1
  And dispara alerta P2 si el contador es > 0 (SAD §observabilidad + architecture.md §9.3)
```

### ES-05 — Conflicto de estado: flag `bumped_read=false` y credencial bumpeada presentada

**Trace:** FR-04 (estado degradado) · architecture.md §9.4

```gherkin
Given el Verifier con `verifier.dome.bumped_read.enabled=false` (estado anómalo — solo aceptable si el comité ejecuta rollback)
When una RP presenta una credencial `LEARCredentialEmployee.4` bumpeada
Then el Verifier responde `503 Service Unavailable` con `error=temporarily_unavailable, error_description="Bumped credential format is temporarily disabled at this tenant"` (no es `410 Gone` porque NO es un sunset — es una desactivación operativa rollbackeable)
  And el log marca `outcome=deny, reason=flag_disabled`
```

### ES-06 — Fallo de dependencia externa: refresh de caché de `tenant_dome_config` falla (DB no responde)

**Trace:** FR-04 · NFR-02

```gherkin
Given el Verifier con caché de `tenant_dome_config` poblada con los valores correctos
  And la BD del tenant DOME deja temporalmente de responder al intento de refresh tras vencer el TTL
When llega una petición de verificación durante la indisponibilidad
Then el Verifier sirve los valores cacheados existentes durante una ventana de gracia documentada (stale-while-error) — fail-open hacia el último valor conocido bueno
  And el log de error registra el fallo del refresh; alerta interna se dispara si la indisponibilidad excede la ventana de gracia
  And tras restablecer la BD, el siguiente refresh vuelve a éxito y el TTL se renueva normalmente
```

### ES-07 — Timeout en validación de firma de credencial (downstream JWKS lento)

**Trace:** FR-04 · NFR-02

```gherkin
Given el Verifier verificando la firma de la credencial contra el JWKS público del Issuer
  And el JWKS endpoint del Issuer no responde dentro del timeout configurado (≤ 5s, SAD §7.1)
When la RP presenta la credencial
Then el Verifier responde `503 Service Unavailable` con `error=temporarily_unavailable`
  And el dispatcher NO determinó formato porque la verificación ocurre antes/durante (depende del orden definido en `VerifyPresentationWorkflow`); el contador relevante es `dome_verifier_request_failures_total{reason=jwks_timeout}`
  And no se emite Access Token (fail-secure)
```

### ES-08 — Fail-secure ante `BumpedCredentialReader` lanzando excepción inesperada

**Trace:** FR-04 (error path) · arquitectura AD-3 fail-secure

```gherkin
Given el `BumpedCredentialReader` lanza una excepción no controlada durante la lectura de una credencial `.4`
When la RP presenta esa credencial
Then el Verifier responde `400 Bad Request` con `error=invalid_request, error_description="Cannot parse credential payload"` SIN incluir traza interna
  And el dispatcher NO cae en cascada al `LegacyCredentialReader` (rompería el determinismo de AD-3 y abriría try/catch como control de flujo — anti-pattern explícito en AD-3 opción B descartada)
  And el error se loguea en `audit.dome.verifier_dispatch` con stack trace internamente para diagnóstico (no se devuelve al cliente)
```

---

## 4. Non-functional requirements (Story-specific)

> Esta Story hereda los NFRs del SRS (NFR-02, NFR-03) y los del feature design (`architecture.md` §9.1). Story-specific NFRs:

| ID | Requirement | Metric | Threshold | Validation method |
|----|-------------|--------|-----------|-------------------|
| NFR-S-145-01 | Latencia añadida por dispatcher dual-format (overhead sobre el flujo Verifier pre-migración) | `dome_verifier_dispatcher_duration_ms` p95 | < 50 ms (la dispatch es lectura JSON + tabla de strings — debe ser despreciable) | k6 micro-benchmark contra `POST /oauth/token` con credenciales sintéticas legacy y bumpeadas |
| NFR-S-145-02 | Tasa de denegación por formato no clasificable | `dome_verifier_dispatcher_total{decision="deny", reason="unclassifiable"} / total` | < 0.1% bajo carga normal con tráfico DOME real (NFR-02 indistinguibilidad) | dashboard cutover §9.3 + alerta P2 si > 0.5% |
| NFR-S-145-03 | Cambio en caliente del flag legacy debe surtir efecto antes del TTL+5s | latencia entre `UPDATE tenant_dome_config` y rechazo `410 Gone` observado | ≤ 65s (TTL 60s + jitter) | integration test que muta config en DB y valida cierre del legacy |

---

## 5. Test matrix

> Mapping AC ↔ tipo de test. Garantiza que toda AC/EC/ES se verifica.

| AC ID | Test type | Asset / file (sugerido) |
|-------|-----------|--------------------------|
| AC-01 | Integration | `verifier/dual-format/LegacyEmployeeDispatchIT.java` (MockMvc + credencial sintética legacy `.3`) |
| AC-02 | Integration | `verifier/dual-format/BumpedEmployeeDispatchIT.java` (MockMvc + credencial sintética bumped `.4`) |
| AC-03 | Integration parametrizado | `verifier/dual-format/LegacyAllTypesDispatchIT.java` (parametrizado sobre `.3/.2/.1`) |
| AC-04 | Integration parametrizado | `verifier/dual-format/BumpedAllTypesDispatchIT.java` (parametrizado sobre `.4/.3/.2`) |
| AC-05 | Integration | `verifier/dual-format/MachineLegacyClientCredentialsIT.java` (M2M flow) |
| AC-06 | Integration | `verifier/dual-format/MachineBumpedClientCredentialsIT.java` (M2M flow) |
| AC-07 | Integration | `verifier/dual-format/SunsetClosedIT.java` (config-driven flag flip; valida `410 Gone`) |
| AC-08 | Unit + Integration | `verifier/dual-format/FlagDefaultsTest.java` + `TenantConfigCacheRefreshIT.java` |
| AC-09 | Integration | `verifier/dual-format/AccessTokenStructureParityIT.java` (snapshot test del Access Token raíz) |
| AC-10 | Integration | `verifier/dual-format/LegacyOffBumpedOnIT.java` |
| EC-01 | Unit | `verifier/dual-format/CredentialSchemaDispatcherTest.java#mixedContextResolvedByType` |
| EC-02 | Unit | `CredentialSchemaDispatcherTest#noVcdmContextResolvedByType` |
| EC-03 | Unit | `CredentialSchemaDispatcherTest#typeOrderIndependent` |
| EC-04 | Integration | `TenantConfigCacheRefreshIT.java#flagTogglesAfterTtl` |
| EC-05 | Integration | `verifier/dual-format/AllowlistPreservationIT.java` |
| EC-06 | Integration | `verifier/dual-format/SchemaProfileGrantEligibilityBumpedIT.java` |
| EC-07 | Integration | `CredentialSchemaDispatcherIT#bumpedWithMissingProfileFailsSecure` |
| ES-01 | Unit | `CredentialSchemaDispatcherTest#missingContextRejects` |
| ES-02 | Unit | `CredentialSchemaDispatcherTest#onlyGenericTypesRejects` |
| ES-03 | Unit | `CredentialSchemaDispatcherTest#unknownConfigIdRejects` |
| ES-04 | Integration | `SunsetClosedIT#legacyReturns410` |
| ES-05 | Integration | `BumpedDisabledIT#bumpedReturns503` |
| ES-06 | Integration | `TenantConfigCacheRefreshIT#staleWhileErrorReturnsCachedValue` |
| ES-07 | Integration | `verifier/dual-format/JwksTimeoutFailureIT.java` |
| ES-08 | Unit + Integration | `CredentialSchemaDispatcherTest#readerExceptionFailsSecure` + IT con reader stub que lanza |
| NFR-S-145-01 | Performance (k6) | `perf/verifier-dual-format-overhead.js` |
| NFR-S-145-02 | Monitor (dashboard) | CloudWatch dashboard `dome-cutover` (no test estático — observabilidad continua) |
| NFR-S-145-03 | Integration | `TenantConfigCacheRefreshIT#flagFlipObservedWithinTtl` |

### Test strategy notes

- **Naming Java:** `*Test.java` para unit (sin Spring context); `*IT.java` para integration (`@SpringBootTest` + `MockMvc` — el Verifier es WebMvc no WebFlux).
- **Fixtures de credencial:** crear vectores sintéticos firmados por una clave de prueba bajo `src/test/resources/fixtures/dome/` con seis ejemplos (`employee-3`, `machine-2`, `label-1`, `employee-4`, `machine-3`, `label-2`). Usar Nimbus JOSE para firmar en el setup del test, no en ficheros estáticos (evita drift de firma).
- **Flag toggling:** los integration tests que prueban defaults y sunset usan `@DynamicPropertySource` o repositorio mock de `TenantConfigPort` — no se modifica `application.yaml` por test.
- **Snapshot test (AC-09):** comparar el shape del Access Token entre legacy y bumpeado con `JSONAssert.assertEquals(expected, actual, JSONCompareMode.STRICT_KEY_ORDER==false)` ignorando timestamps y `jti`.

---

## 6. Visual acceptance criteria

**N/A — Story sin superficie visual.**

---

## Backward-trace (AC → SRS)

| AC ID | SRS section | FR / NFR |
|-------|-------------|----------|
| AC-01 | §3.1 + §3.2 | FR-04 + NFR-02 |
| AC-02 | §3.1 + §3.2 | FR-04 + FR-06a + NFR-02 |
| AC-03 | §3.1 | FR-04 |
| AC-04 | §3.1 | FR-04 + FR-05 + FR-06a |
| AC-05 | §3.1 + §3.2 | FR-04 + NFR-02 |
| AC-06 | §3.1 | FR-04 + FR-06a |
| AC-07 | §3.1 + §3.2 | FR-04 (sunset) + NFR-04 |
| AC-08 | §3.1 | FR-04 + architecture.md §9.4 (defaults) |
| AC-09 | §3.2 | NFR-02 + FR-06a |
| AC-10 | §3.1 | FR-04 + architecture.md §9.4 |
| EC-01..EC-07 | §3.1 (extensión) | FR-04 (extensión) |
| ES-01..ES-08 | §3.1 + §3.2 | FR-04 (error paths) + NFR-02 (indistinguibilidad funcional de errores) |
| NFR-S-145-01 | new (Story-specific) | derivado de NFR-02 (indistinguibilidad observable de latencia) |
| NFR-S-145-02 | new (Story-specific) | derivado de NFR-02 |
| NFR-S-145-03 | new (Story-specific) | derivado de FR-04 + NFR-04 |

---

## Status Lifecycle

| Status | Who sets it | When |
|--------|-------------|------|
| **Draft** | `software-architect` agent | Initial creation under `/enrich-us EUDISTACK-145` |
| **Review** | Human | Sent for PO + Architect review |
| **Approved** | Human (PO + Architect consensus) | Ready for `/implement` |

## Changelog

| Date | Change | Author |
|------|--------|--------|
| 2026-05-19 | Initial draft (Stage 2b — `/enrich-us EUDISTACK-145`). 10 AC + 7 EC + 8 ES + 3 NFR-S. | software-architect |
