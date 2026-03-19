<div align="center">

# EUDIStack Core Verifier

**OAuth 2.0 Authorization Server with OpenID4VP for verifiable credential-based authentication.**

Part of [EUDIStack](https://github.com/in2workspace) — European Digital Identity Infrastructure for Organizations.

</div>

---

## Overview

The Verifier is an OAuth 2.0 / OpenID Connect Authorization Server that extends the standard authentication flow with **OpenID for Verifiable Presentations (OID4VP)**. It allows relying parties to authenticate users and organizations through verifiable credentials, supporting both human-to-machine (H2M) and machine-to-machine (M2M) scenarios.

It acts as the trust anchor for the EUDIStack ecosystem: any application that needs to authenticate a holder does so through the Verifier.

### Key Features

- **OpenID Connect + OID4VP** — Standard OIDC flows enhanced with verifiable presentation requests
- **DCQL queries** — Dynamic Credential Query Language for flexible credential matching
- **SD-JWT VC + W3C support** — Dual-format credential verification (RFC 9901 and W3C VC Data Model)
- **Multi-tenant** — Tenant isolation via OIDC client registration with signed tenant claims
- **Hexagonal architecture** — Clean separation of domain, application, and infrastructure layers

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Java 25 |
| Framework | Spring Boot 3.5 + WebFlux (reactive) |
| Security | Spring Authorization Server + OAuth2 |
| Architecture | Hexagonal (Ports & Adapters), 2 bounded contexts |
| Crypto | Nimbus JOSE JWT, BouncyCastle |
| Build | Gradle 9.3 |
| Tests | JUnit 5 + ArchUnit (17 architecture rules) |
| Observability | Micrometer + OpenTelemetry |

## Getting Started

### Prerequisites

- Java 25 (Eclipse Temurin or Azul Zulu)
- Docker (for running dependent services)

### Build

```bash
./gradlew build
```

### Run Tests

```bash
./gradlew test
```

Coverage reports are generated at `build/jacocoHtml/`.

### Run with Docker Compose

```bash
make up
```

## Configuration

The application is configured via `application.yaml` with environment variable overrides.

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | HTTP server port | `8082` |
| `VERIFIER_FRONTEND_PORTALURL` | External Angular SPA URL | `http://localhost:4200` |
| `VERIFIER_BACKEND_URL` | Public URL of the verifier | `http://localhost:8082` |
| `VERIFIER_BACKEND_TOKEN_ACCESSTOKEN_EXPIRATION` | Access token TTL (seconds) | `900` |
| `VERIFIER_BACKEND_LOCALFILES_CLIENTSPATH` | External clients YAML path | _(embedded)_ |
| `VERIFIER_BACKEND_LOCALFILES_TRUSTEDISSUERSPATH` | External trusted issuers YAML path | _(embedded)_ |
| `VERIFIER_BACKEND_LOCALFILES_DCQLPATH` | External DCQL profiles YAML path | _(embedded)_ |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry collector endpoint | `http://localhost:4318` |

## CI/CD

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `build.yml` | Push / PR to `main` | Build, test, JaCoCo coverage summary |
| `snapshot.yml` | PR to `main` | Snapshot Docker image (`v3.0.0-pr-N`) to DockerHub + ECR |
| `release.yml` | Manual | `docker-push` (final image) or `tag-create` (GitHub Release) |

## Project Structure

```
src/main/java/es/in2/vcverifier/
├── oauth2/                  # OAuth2 / OIDC bounded context
│   ├── application/workflow/ # Authorization & token workflows
│   ├── domain/              # Models, services, exceptions
│   └── infrastructure/      # Controllers, filters, adapters
├── verifier/                # OID4VP bounded context
│   ├── application/workflow/ # Presentation verification workflows
│   ├── domain/              # Models, services, exceptions
│   └── infrastructure/      # Controllers, adapters (status list, claims, schemas)
└── shared/                  # Cross-cutting: crypto, config, properties
```

## Standards & Protocols

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID for Verifiable Presentations 1.0 (OID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [SD-JWT VC (RFC 9901)](https://datatracker.ietf.org/doc/rfc9901/)
- [DCQL (Digital Credentials Query Language)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l)
- [DPoP (RFC 9449)](https://datatracker.ietf.org/doc/rfc9449/)
- [HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Licensed under the [Apache License 2.0](LICENSE).

## Contact

- **Organization:** [IN2, Ingeniería de la Información](https://in2.es)
- **Email:** [dome@in2.es](mailto:dome@in2.es)
</div>
