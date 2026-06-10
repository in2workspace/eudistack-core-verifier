# EUDISTACK-145: US-08 Verifier dual-format read (legacy + bumpeado) con sunset 6–12m — User Story (functional spec)

> **Naturaleza del documento — User Story spec = Propuesta funcional de la Story.**
>
> Este documento es el **resultado del comando `/enrich-us EUDISTACK-145`** (sub-output del `software-architect` Stage 2b). Captura la propuesta funcional **per-Story**: qué entrega esta Story, para quién, qué slice del feature implementa y qué queda fuera de alcance.
>
> Los acceptance criteria canónicos (G/W/T exhaustivos, edge cases, error scenarios, test matrix) viven en [`acceptance-criteria.md`](acceptance-criteria.md). El detalle técnico (archivos, ports, ADR, mapeo AC→tasks) vive en [`technical-design.md`](technical-design.md). El breakdown de tareas vive en [`tasks.md`](tasks.md).

## 1. Referencias

| Campo | Valor |
|-------|-------|
| Status | **Draft** |
| Date | 2026-05-19 |
| Story Jira | [`EUDISTACK-145`](https://eudistack.atlassian.net/browse/EUDISTACK-145) |
| Feature parent | [`EUDISTACK-12`](https://eudistack.atlassian.net/browse/EUDISTACK-12) — DOME — Standalone-to-SaaS Tenant Migration |
| Feature SRS | [`../specs/srs.md`](../specs/srs.md) |
| User story (feature-level) | [`../specs/user-stories.md`](../specs/user-stories.md) — `US-08` |
| Feature architecture | [`../specs/architecture.md`](../specs/architecture.md) — AD-3, §3.3, §6.2, §9.4 |
| Acceptance criteria (canonical) | [`acceptance-criteria.md`](acceptance-criteria.md) |
| Tech design (per-Story) | [`technical-design.md`](technical-design.md) |
| Tasks (per-Story) | [`tasks.md`](tasks.md) |
| Author | software-architect (Stage 2b) |

---

## §1 — Propuesta

### 1.1 Resumen funcional

Esta Story habilita al **Verifier** del producto EUDIStack para que pueda **leer dos formatos de credencial DOME simultáneamente** durante el sunset de 6–12 meses posterior al cutover:

- Credenciales **legacy** emitidas antes del corte: `LEARCredentialEmployee.3`, `LEARCredentialMachine.2`, `gx:LabelCredential.1` (formato W3C VCDM v1.1 con `vc` wrap nativo en el JWT).
- Credenciales **bumpeadas** emitidas tras el corte: `LEARCredentialEmployee.4`, `LEARCredentialMachine.3`, `gx:LabelCredential.2` (formato W3C VCDM v2.0 canónico, sin `vc` wrap en la credencial).

La discriminación entre ambos formatos es **determinista** en base a `@context` + `type[]` (no try/catch). Para credenciales VCDM v2.0, el **Access Token construido por el Verifier** envuelve la credencial bajo el claim `vc` (FR-06a); para credenciales v1.1, el `vc` wrap ya forma parte de la propia credencial y no se aplica wrap adicional. El comportamiento se preserva para las dos clases de cliente del Verifier que opera DOME hoy: **Relying Parties con allowlist** y **máquinas sin registro** (M2M client_credentials). El sunset se desactiva por configuración (sin redeploy de código) mediante un feature flag que rechaza credenciales legacy con `410 Gone` una vez cerrado.

### 1.2 Por qué esta Story (valor)

Sin esta Story, el bumpeo de schemas al estándar W3C VCDM v2.0 (FR-05, US-02/US-03) **rompería** a todas las Relying Parties DOME activas que hoy verifican credenciales legacy — obligándolas a actualizar su integración en plazo crítico (cutover ≤ 30 min de downtime). Con el dual-format read, las RPs DOME pueden continuar verificando exactamente como hoy y migrar a su propio ritmo durante el sunset 6–12m. Cumple además FR-06a (wrap `vc` en Access Token para VCDM v2.0) y preserva los mecanismos de admisión vigentes (allowlist + máquinas sin registro), elemento crítico de NFR-02 (indistinguibilidad funcional pre/post-migración).

### 1.3 Slice del feature que implementa

Implementa el slice **Verifier** del feature (`eudistack-core-verifier`), centrado en `architecture.md` §3.3 (componentes Verifier: `CredentialSchemaDispatcher`, `LegacyCredentialReader`, `BumpedCredentialReader`, `AccessTokenBuilder`), AD-3 (dispatcher determinista + wrap `vc` exclusivo en Access Token), §6.2 (secuencia RP → Verifier dual-format → Access Token) y §9.4 (feature flags `verifier.dome.legacy_read.enabled`, `verifier.dome.bumped_read.enabled`). No introduce APIs nuevas hacia las RPs: el endpoint `POST /oauth/token` mantiene contrato.

### 1.4 Actores y journey

| Actor | Acción | Outcome |
|-------|--------|---------|
| Relying Party DOME (allowlist o máquina sin registro) | Presenta una credencial DOME legacy `.3/.2/.1` al endpoint `POST /oauth/token` del Verifier | Recibe `200 OK` con un Access Token cuyo claim `vc` contiene la credencial legacy completa y verificable, sin haber modificado su integración. |
| Relying Party DOME | Presenta una credencial DOME bumpeada `.4/.3/.2` (VCDM v2.0) al mismo endpoint | Recibe `200 OK` con un Access Token cuyo claim `vc` contiene la credencial v2.0 envuelta (FR-06a), con la **misma estructura externa** que el caso legacy desde la perspectiva del consumidor. |
| Operador del tenant EUDIStack | Al cierre del sunset 6–12m, desactiva el flag `verifier.dome.legacy_read.enabled` por configuración | El Verifier rechaza credenciales legacy con `410 Gone` + audit log; el resto de credenciales bumpeadas siguen verificando. Sin redeploy. |
| Máquina M2M sin registro previo | Inicia un `client_credentials` grant presentando una credencial Machine legacy `.2` o bumpeada `.3` | Recibe Access Token equivalente — el dual-format read aplica también al flujo M2M. |

### 1.5 KPIs / métricas de éxito (opcional)

| Métrica | Cómo se mide | Threshold |
|---------|--------------|-----------|
| Tráfico dual-format por formato | `dome_verifier_dispatcher_total{tenant=dome, format=legacy\|bumped, decision=permit}` | RPs en sunset migran progresivamente de `legacy` a `bumped`; usable para decidir cierre del flag legacy. |
| Verifier dispatcher deny rate | `dome_verifier_dispatcher_total{decision=deny} / total` | < 0.5% (NFR-02 indistinguibilidad). |
| Legacy replay post-sunset | `dome_verifier_legacy_replay_after_sunset_total` | == 0 una vez el flag legacy está OFF (alerta P2 si > 0). |

---

## §2 — Acceptance Criteria (resumen funcional)

> Resumen no exhaustivo. G/W/T canónicos en [`acceptance-criteria.md`](acceptance-criteria.md).

- [ ] **AC-1**: Una RP DOME en allowlist presenta una credencial legacy `LEARCredentialEmployee.3` y obtiene un Access Token válido con la credencial bajo el claim `vc`, sin haber cambiado nada en su lado.
- [ ] **AC-2**: La misma RP presenta una credencial bumpeada `LEARCredentialEmployee.4` (VCDM v2.0) y obtiene un Access Token válido con la credencial envuelta bajo `vc` (FR-06a) — misma estructura externa que AC-1.
- [ ] **AC-3**: Los tres tipos productivos están cubiertos por el dispatcher (Employee, Machine, Label) tanto en variante legacy como bumpeada.
- [ ] **AC-4**: Una máquina sin registro (M2M `client_credentials`) opera idénticamente: presenta `LEARCredentialMachine.2` o `.3` y obtiene Access Token con `vc` wrap aplicado según formato.
- [ ] **AC-5**: Al cierre del sunset, el Operador desactiva el flag legacy por configuración y el Verifier rechaza credenciales legacy con `410 Gone` + razón auditable; los bumpeados siguen verificando.
- [ ] **AC-6**: La activación es coordinada por dos flags independientes — `verifier.dome.bumped_read.enabled` (default `true` desde el despliegue) y `verifier.dome.legacy_read.enabled` (default `true` hasta cierre del sunset).
- [ ] **AC-7**: El comportamiento es **funcionalmente indistinguible** (códigos, forma de error, claims del Access Token) del estado pre-migración para credenciales legacy (NFR-02).

> Detalle G/W/T + edge cases (`@context` ambiguo, mezcla de versiones, allowlist vacía, …) + error scenarios + test matrix → [`acceptance-criteria.md`](acceptance-criteria.md). Mirror sintético para `task-planner` → `technical-design.md` §2.

---

## §3 — Out of scope

- **Emisión** de credenciales legacy o bumpeadas — fuera de scope. La cubren US-02 (Onboarding) / US-03 (DEKRA) sobre el DOME API Adapter + Issuer CORE. El Issuer no envuelve VCDM v2.0 bajo `vc` (FR-06b); ese wrap es **exclusivo del Verifier** al construir el Access Token.
- **Migración de datos históricos** desde IONOS al RDS del tenant DOME — fuera de scope, lo cubre US-05.
- **Migración de claves de firma** y dual JWKS — fuera de scope, lo cubre US-06. Esta Story asume que la clave pública DOME está disponible en el JWKS para verificar firmas sin importar la antigüedad de la credencial.
- **Cutover plan, secuencia de activación de flags, runbook de rollback** — fuera de scope, lo cubre US-09. Esta Story solo declara los flags y su default; la coordinación temporal pertenece a US-09.
- **Soporte cross-tenant del dispatcher.** El dispatcher dual-format se diseña para gobernarse por configuración de tenant (`tenant_dome_config`); su activación para tenants distintos de `dome` no entra en esta Story. La estructura del código sí permite reuso futuro (AD-3 + AD-2 bumpeo global).
- **Convergencia hacia un único formato post-sunset.** El cierre del flag legacy es una decisión operativa del comité y no implica refactor del dispatcher en esta Story. El borrado del `LegacyCredentialReader` se planificará como deuda saldable cuando el contador `dome_verifier_dispatcher_total{format=legacy,decision=permit}` permanezca a cero ≥ 30 días tras el cierre del flag.
- **Cambios en la API hacia las Relying Parties.** El contrato `POST /oauth/token` y el formato del Access Token consumido por las RPs no cambian respecto al pre-migración: por eso esta Story preserva NFR-02.
- **Persistencia per-tenant del dispatcher**. La selección "DOME ↔ schemas DOME" se hace por inspección de la credencial (`@context` + `type[]`), no por look-up `tenant_id → reader`. Si en el futuro hace falta resolver por tenant, se introduce en otra Story.

---

## §4 — Dependencias funcionales con otras Stories

> Solo dependencias **funcionales**. Las dependencias técnicas + mecanismos de deploy seguro viven en `technical-design.md` §3.7.1.

| Story dependencia | Tipo | Motivo |
|-------------------|------|--------|
| **US-01 (EUDISTACK-138) — Alta tenant DOME** | Recomendada (no bloqueante) | El dispatcher dual-format se puede desarrollar y testar contra credenciales sintéticas sin tenant `dome` activado; el smoke test en STG con tenant DOME real depende de US-01 estar `Done`. |
| **US-09 (EUDISTACK-483) — Cutover plan** | Coordinación (no bloqueante de desarrollo) | El comité de cutover decide cuándo encender los flags `verifier.dome.*` en producción. El código de esta Story aterriza con flags ON por defecto, listo para ser activado por el cutover. |

> **Sin dependencias de negocio entre Stories.** Cumple INVEST (`user-stories.md` §US-08 — Independencia): la Story se desarrolla, prueba y mergea sola con flags neutros (`bumped_read=true` desde el despliegue + `legacy_read=true` durante el sunset). Activación productiva coordinada por US-09.

---

## §5 — Visual specs (si aplica)

**N/A — Story sin superficie visual.** Esta Story toca exclusivamente backend del Verifier (`eudistack-core-verifier`). No introduce UI ni modificaciones en Portal Console / MFEs / Wallet PWA. La superficie visual del feature DOME Migration está cubierta dentro de `EUDISTACK-37 EUDIW Bootstrap` (PRD §5 — heredada sin variantes específicas DOME en esta release).

---

## Status Lifecycle

| Status | Who sets it | When |
|--------|-------------|------|
| **Draft** | `software-architect` agent | Initial creation under `/enrich-us EUDISTACK-145` (Stage 2b) |
| **Review** | Human | User Story spec sent for functional review (PO + stakeholders) |
| **Approved** | PO | User Story spec approved, ready for tech-design refinement & task generation |

## Changelog

| Date | Change | Author |
|------|--------|--------|
| 2026-05-19 | Initial draft (Stage 2b — `/enrich-us EUDISTACK-145`). | software-architect |
