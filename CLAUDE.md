# Verifier — Repo Guide for Claude

> **Per-repo CLAUDE.md.** Loaded only when working inside this repo. The
> SDD Constitution lives in `../eudistack-platform-dev/CLAUDE.md`.

## Identity

Java 25 + Spring Boot 3.5 + Spring **WebMvc** implementation of the
EUDIStack **Verifier**. Implements OID4VP 1.0 with DCQL queries,
validates SD-JWT VC presentations from wallets, integrates with
identity providers via OpenID Connect.

Repo group: `com.eudistack` · current version: see `build.gradle`.

## Tech stack

- **Java 25** (Gradle toolchain)
- **Spring Boot 3.5.11** + **WebMvc** (servlet, not reactive)
- **PostgreSQL** (schema-per-tenant) via JPA / JDBC
- **Flyway** for migrations
- **Nimbus JOSE+JWT** + BouncyCastle for crypto
- **RestTemplate / RestClient** for outbound HTTP
- **Testcontainers**, **MockMvc** for integration tests
- **Checkstyle**, **JaCoCo**, **OWASP dependency-check**

## Architecture (hexagonal)

Same layer rules as Issuer but on **servlet stack** (no Reactor
Context):

- `domain/` — entities, value objects, domain services (no Spring imports)
- `application/` — use cases, ports
- `infrastructure/` — adapters (controllers, JPA repos, RestClient, config)

Strict rules: `../eudistack-platform-dev/.claude/rules/hexagonal-discipline.md`.

## Multi-tenancy

- Tenant resolved from `X-Tenant-Id` header via a `TenantContextHolder` backed by `ThreadLocal` (servlet stack — unlike Issuer/EBW which use Reactor Context).
- One PostgreSQL schema per tenant; `search_path` reset on connection release.
- See `../eudistack-platform-dev/.claude/rules/tenant-isolation.md`.

## Common commands

> **Dev stack runs in Docker** via `make up` from `eudistack-platform-dev`.

| Task | Command |
|------|---------|
| Compile | `./gradlew compileJava` |
| Unit tests | `./gradlew test` |
| Integration tests | `./gradlew integrationTest` |
| Full check | `./gradlew check` |
| Rebuild Docker image | `cd ../eudistack-platform-dev && make rebuild-verifier-service` |
| Tail logs | `cd ../eudistack-platform-dev && make logs-verifier` |
| OWASP dependency check | `./gradlew dependencyCheckAnalyze` |

## Testing conventions

- `*Test.java` — unit (JUnit 5 + Mockito, no Spring).
- `*IT.java` — integration (Spring + Testcontainers Postgres).
- MVC endpoints: `MockMvc` (NOT WebTestClient — this repo is servlet stack).
- Naming: `Class_methodUnderTest_expectedBehavior`.

## Protocols implemented

- **OID4VP 1.0** — Verifiable Presentations.
- **DCQL** — Digital Credentials Query Language (canonical query format).
- **SD-JWT VC** (RFC 9901) — parsing + verification.
- **DPoP** (RFC 9449) — on token endpoints.
- **OpenID Connect** — for human authentication flows.

Normative invariants:
`../eudistack-platform-dev/.claude/rules/protocol-compliance.md`.

## Code style

- Lombok for constructors / getters.
- Constructor injection only.
- Package-by-feature inside hexagonal layers.
- **Servlet stack:** no Reactor types. Use `Optional`, `Stream`, plain Java.
- Logging: SLF4J via Lombok `@Slf4j`.

## Where to find specs

`../eudistack-platform-dev/docs/EUDISTACK-NNN-*/EUDISTACK-MMM/`.

## Git workflow

- **Squash merge to `main`.** One commit per logical change.
- Conventional Commits + Story footer.
- Branch-guard hook blocks direct commits to `main`.

## References

- Constitution: [`../eudistack-platform-dev/CLAUDE.md`](../eudistack-platform-dev/CLAUDE.md)
- SAD: [`../eudistack-platform-dev/docs/_shared/architecture/sad.md`](../eudistack-platform-dev/docs/_shared/architecture/sad.md)
- Skills: `java-spring-hexagonal`, `code-review-checklist`, `commit-conventions`
- Rules: `hexagonal-discipline`, `tenant-isolation`, `protocol-compliance`
