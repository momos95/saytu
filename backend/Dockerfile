# syntax=docker/dockerfile:1
# AfriCodeShield backend (API). Build context: ./backend
# The scan worker image (phase 4) extends this build with the scanner binaries.

# ---------- build ----------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
# Dependency layer cached independently of the sources
COPY pom.xml .
COPY acs-core/pom.xml acs-core/
COPY acs-app/pom.xml acs-app/
RUN --mount=type=cache,target=/root/.m2 mvn -B -q -pl acs-app -am dependency:go-offline -DskipTests || true
COPY acs-core/src acs-core/src
COPY acs-app/src acs-app/src
# Unit tests run here; Testcontainers integration tests (*IT) need Docker and run in CI with `mvn verify`.
ARG SKIP_TESTS=false
RUN --mount=type=cache,target=/root/.m2 mvn -B -pl acs-app -am package -DskipTests=${SKIP_TESTS}

# ---------- runtime ----------
FROM eclipse-temurin:21-jre-alpine AS runtime
LABEL org.opencontainers.image.title="africodeshield-api" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/africodeshield/africodeshield"
RUN addgroup -S -g 10001 acs && adduser -S -u 10001 -G acs -h /app acs
WORKDIR /app
COPY --from=build --chown=acs:acs /src/acs-app/target/africodeshield.jar app.jar
USER 10001:10001
EXPOSE 8080
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom"
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/actuator/health/readiness | grep -q '"UP"' || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
