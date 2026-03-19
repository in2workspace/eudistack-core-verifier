# Contributing to EUDIStack Verifier Core

Thank you for your interest in contributing to the EUDIStack Verifier Core Service.

## Development Setup

### Prerequisites

- Docker 20.10+
- Docker Compose v2+
- Java 25 (only for running tests locally)

### Running the stack

The Verifier is orchestrated from [eudistack-platform-dev](https://github.com/nicerloop/eudistack-platform-dev). Do not run the service locally with `./gradlew bootRun` — always use Docker Compose.

```bash
# From the platform-dev repo:
make up
```

### Running tests

```bash
./gradlew test
```

## Contributing Workflow

1. All work follows the **spec-driven development** workflow defined in the platform-dev repo (`/specify` -> `/plan` -> `/tasks` -> review).
2. Fork the repo and create your branch from `main`.
3. If you've added code that should be tested, add tests. Aim to maintain the ~1.15:1 test-to-code ratio.
4. Ensure the test suite passes (`./gradlew test`).
5. Follow the existing hexagonal architecture: domain has zero framework dependencies, adapters in infrastructure.
6. Submit a pull request. All PRs are **squash merged** into `main`.

## Architecture

The codebase follows hexagonal architecture with 3 bounded contexts:

```
es.in2.vcverifier/
├── verifier/       # OID4VP verification (domain, application, infrastructure)
├── oauth2/         # OAuth2 Authorization Server (domain, application, infrastructure)
└── shared/         # Cross-cutting: crypto, config, models
```

17 ArchUnit rules enforce layer boundaries, naming conventions, and bounded context isolation.

## Code Style

- Java 25, Spring Boot 3 + WebFlux (reactive)
- 4 spaces indentation
- Checkstyle enforced via `config/checkstyle/checkstyle.xml`
- Follow existing naming conventions (see EUDI-004 FR-NAME in platform-dev docs)

## Bug Reports

Report bugs via [GitHub Issues](https://github.com/nicerloop/eudistack-core-verifier/issues). Include:

- Steps to reproduce
- Expected vs actual behavior
- Verifier version and Docker image tag

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE.md).
