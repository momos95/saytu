# syntax=docker/dockerfile:1
# SAYTU backend (API). Build context: ./backend
# The scan worker image (phase 4) extends this build with the scanner binaries.

# ---------- build ----------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
# Extra CA certificates (build context "ca" = ./data/ca): internal CA or HTTPS inspection proxy
# (Netskope, Zscaler...). Without them Maven cannot download dependencies behind such a proxy.
COPY --from=ca / /tmp/extra-ca/
RUN set -e; for f in /tmp/extra-ca/*.pem /tmp/extra-ca/*.crt /tmp/extra-ca/*.cer; do \
      [ -f "$f" ] || continue; \
      keytool -importcert -noprompt -cacerts -storepass changeit -alias "extra-$(basename "$f")" -file "$f"; \
    done
# Dependency layer cached independently of the sources
COPY pom.xml .
COPY saytu-core/pom.xml saytu-core/
COPY saytu-git/pom.xml saytu-git/
COPY saytu-app/pom.xml saytu-app/
RUN --mount=type=cache,target=/root/.m2 mvn -B -q -pl saytu-app -am dependency:go-offline -DskipTests || true
COPY saytu-core/src saytu-core/src
COPY saytu-git/src saytu-git/src
COPY saytu-app/src saytu-app/src
# Unit tests run here; Testcontainers integration tests (*IT) need Docker and run in CI with `mvn verify`.
ARG SKIP_TESTS=false
RUN --mount=type=cache,target=/root/.m2 mvn -B -pl saytu-app -am package -DskipTests=${SKIP_TESTS}

# ---------- runtime ----------
FROM eclipse-temurin:21-jre-alpine AS runtime
LABEL org.opencontainers.image.title="saytu-api" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/momos95/saytu"
RUN addgroup -S -g 10001 saytu && adduser -S -u 10001 -G saytu -h /app saytu
# Same extra CA certificates at runtime, for calls to Git platforms through an inspection proxy
COPY --from=ca / /tmp/extra-ca/
RUN set -e; for f in /tmp/extra-ca/*.pem /tmp/extra-ca/*.crt /tmp/extra-ca/*.cer; do \
      [ -f "$f" ] || continue; \
      keytool -importcert -noprompt -cacerts -storepass changeit -alias "extra-$(basename "$f")" -file "$f"; \
    done; rm -rf /tmp/extra-ca
WORKDIR /app
COPY --from=build --chown=saytu:saytu /src/saytu-app/target/saytu.jar app.jar
USER 10001:10001
EXPOSE 8080
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom"
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/actuator/health/readiness | grep -q '"UP"' || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
