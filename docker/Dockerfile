# ---- Build stage ----
FROM eclipse-temurin:25-jdk-alpine AS build

ARG SKIP_TESTS=false

WORKDIR /workspace

# Copy Gradle wrapper first (cacheable layer — rarely changes)
COPY gradlew ./
COPY gradle/wrapper/ gradle/wrapper/
RUN chmod +x gradlew && ./gradlew --version --no-daemon

# Copy build config (cacheable layer — changes less often than source)
COPY build.gradle settings.gradle ./
COPY config/ config/
RUN ./gradlew dependencies --no-daemon || true

# Copy source and build
COPY src/ src/
RUN if [ "$SKIP_TESTS" = "true" ]; then \
      ./gradlew build --no-daemon -x test -x checkstyleMain -x checkstyleTest; \
    else \
      ./gradlew build --no-daemon; \
    fi

# ---- Runtime stage ----
FROM eclipse-temurin:25-jre-alpine

LABEL org.opencontainers.image.title="eudistack-core-verifier" \
      org.opencontainers.image.description="OAuth 2.0 Authorization Server with OID4VP for verifiable credential-based authentication" \
      org.opencontainers.image.vendor="Altia" \
      org.opencontainers.image.source="https://github.com/in2workspace/eudistack-core-verifier" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar app.jar

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
