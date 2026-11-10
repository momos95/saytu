# syntax=docker/dockerfile:1
# SAYTU backend. Build context: ./backend
# Extra build contexts: "ca" (PEM certificates to trust, ./data/ca) and "scanners" (rules, ./scanners).
#   target "api"    : REST API (Alpine JRE, no scanner)
#   target "worker" : same application with SAYTU_WORKER_ENABLED=true, git, prlimit and the scanners

# ---------- scanner binaries: pinned versions, SHA-256 / commit checked ----------
FROM ubuntu:24.04 AS tools
ARG OPENGREP_VERSION=1.33.1
ARG OPENGREP_SHA256=46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808
ARG TRIVY_VERSION=0.76.1
ARG TRIVY_SHA256=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG PHPCS_VERSION=4.0.2
ARG PHPCS_COMMIT=74ee2d4df09b70996c1e0fafca7079fc0bbb9ec0
ARG SQLFLUFF_VERSION=4.4.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ca / /tmp/extra-ca/
RUN set -e; for f in /tmp/extra-ca/*.pem /tmp/extra-ca/*.crt /tmp/extra-ca/*.cer; do \
      [ -f "$f" ] || continue; cp "$f" "/usr/local/share/ca-certificates/extra-$(basename "${f%.*}").crt"; \
    done; update-ca-certificates >/dev/null
WORKDIR /opt/saytu/tools
# Opengrep is self-extracting (~250 MB): it is unpacked once here (opengrep-runtime), read-only at run time
RUN set -e; \
    curl -fsSL -o opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86"; \
    echo "${OPENGREP_SHA256}  opengrep" | sha256sum -c -; \
    curl -fsSL -o trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    echo "${TRIVY_SHA256}  trivy.tgz" | sha256sum -c -; \
    tar -xzf trivy.tgz trivy; rm trivy.tgz; \
    curl -fsSL -o gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    echo "${GITLEAKS_SHA256}  gitleaks.tgz" | sha256sum -c -; \
    tar -xzf gitleaks.tgz gitleaks; rm gitleaks.tgz; \
    chmod 0755 opengrep trivy gitleaks; chown root:root opengrep trivy gitleaks; \
    XDG_CACHE_HOME=/opt/saytu/tools/opengrep-runtime ./opengrep --version; \
    ./trivy --version; ./gitleaks version
# PHP_CodeSniffer runs from its sources (no Composer dependency); the tag must point to the expected commit
RUN set -e; \
    git -c advice.detachedHead=false clone --quiet --depth 1 --branch "${PHPCS_VERSION}" \
      https://github.com/PHPCSStandards/PHP_CodeSniffer.git phpcs; \
    test "$(git -C phpcs rev-parse HEAD)" = "${PHPCS_COMMIT}"; \
    rm -rf phpcs/.git phpcs/tests
# SQLFluff in its own virtual environment (Python of Ubuntu 24.04, same path in the build and worker images)
RUN set -e; python3 -m venv /opt/saytu/tools/sqlfluff; \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt /opt/saytu/tools/sqlfluff/bin/pip install --no-cache-dir --disable-pip-version-check \
      "sqlfluff==${SQLFLUFF_VERSION}"; \
    /opt/saytu/tools/sqlfluff/bin/sqlfluff --version
COPY --from=scanners opengrep/rules /opt/saytu/rules/opengrep
COPY --from=scanners gitleaks /opt/saytu/rules/gitleaks
COPY --from=scanners checkstyle /opt/saytu/rules/checkstyle
# The SAYTU rules must pass their own tests ("ruleid:" must match, "ok:" must not)
RUN XDG_CACHE_HOME=/opt/saytu/tools/opengrep-runtime HOME=/tmp /opt/saytu/tools/opengrep --test \
      --disable-version-check /opt/saytu/rules/opengrep/saytu \
    && chmod -R a+rX,go-w /opt/saytu

# ---------- Checkstyle and PMD jars, resolved by Maven (checksums verified) ----------
FROM maven:3.9-eclipse-temurin-21 AS jvmtools
COPY --from=ca / /tmp/extra-ca/
RUN set -e; for f in /tmp/extra-ca/*.pem /tmp/extra-ca/*.crt /tmp/extra-ca/*.cer; do \
      [ -f "$f" ] || continue; \
      keytool -importcert -noprompt -cacerts -storepass changeit -alias "extra-$(basename "$f")" -file "$f"; \
    done
COPY tools/checkstyle.pom.xml tools/pmd.pom.xml /tmp/tools/
COPY --from=scanners checkstyle /opt/saytu/rules/checkstyle
RUN --mount=type=cache,target=/root/.m2 set -e; \
    mvn -B -q -f /tmp/tools/checkstyle.pom.xml dependency:copy-dependencies -DincludeScope=runtime \
      -DoutputDirectory=/opt/saytu/tools/checkstyle; \
    mvn -B -q -f /tmp/tools/pmd.pom.xml dependency:copy-dependencies -DincludeScope=runtime \
      -DoutputDirectory=/opt/saytu/tools/pmd; \
    java -cp '/opt/saytu/tools/checkstyle/*' com.puppycrawl.tools.checkstyle.Main --version; \
    java -cp '/opt/saytu/tools/pmd/*' net.sourceforge.pmd.cli.PmdCli --version; \
    printf 'class A { }\n' > /tmp/A.java; \
    java -cp '/opt/saytu/tools/checkstyle/*' com.puppycrawl.tools.checkstyle.Main \
      -c /opt/saytu/rules/checkstyle/saytu-checks.xml /tmp/A.java

# ---------- ESLint, typescript-eslint, eslint-plugin-security ----------
FROM node:22.23.3-bookworm-slim AS eslint
COPY --from=ca / /tmp/extra-ca/
RUN set -e; : > /tmp/extra-ca.pem; for f in /tmp/extra-ca/*.pem /tmp/extra-ca/*.crt /tmp/extra-ca/*.cer; do \
      [ -f "$f" ] && cat "$f" >> /tmp/extra-ca.pem || true; done
WORKDIR /opt/saytu/tools/eslint
COPY --from=scanners eslint/package.json eslint/eslint.config.mjs ./
# --ignore-scripts: no install script of any package runs
RUN set -e; NODE_EXTRA_CA_CERTS=/tmp/extra-ca.pem npm install --ignore-scripts --omit=dev --no-audit --no-fund; \
    mkdir -p /tmp/smoke && printf 'export const f = (x: any) => x;\n' > /tmp/smoke/a.ts; \
    cd /tmp && node /opt/saytu/tools/eslint/node_modules/eslint/bin/eslint.js \
      --config /opt/saytu/tools/eslint/eslint.config.mjs --format json /tmp/smoke > /tmp/smoke.json || test $? -eq 1; \
    grep -q '"@typescript-eslint/no-explicit-any"' /tmp/smoke.json; \
    mkdir -p /opt/saytu/tools/node/bin && cp /usr/local/bin/node /opt/saytu/tools/node/bin/node; \
    chmod -R a+rX,go-w /opt/saytu

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
# git, php, cppcheck and python3 are used by the scan engine tests (real clones and real tool runs)
RUN apt-get update && apt-get install -y --no-install-recommends git php-cli php-xml cppcheck python3 \
    && rm -rf /var/lib/apt/lists/*
# Dependency layer cached independently of the sources
COPY pom.xml .
COPY saytu-core/pom.xml saytu-core/
COPY saytu-git/pom.xml saytu-git/
COPY saytu-scan/pom.xml saytu-scan/
COPY saytu-app/pom.xml saytu-app/
RUN --mount=type=cache,target=/root/.m2 mvn -B -q -pl saytu-app -am dependency:go-offline -DskipTests || true
COPY saytu-core/src saytu-core/src
COPY saytu-git/src saytu-git/src
COPY saytu-scan/src saytu-scan/src
COPY saytu-app/src saytu-app/src
# The scan engine tests run the real scanners on a generated repository (nothing is simulated)
COPY --from=tools /opt/saytu /opt/saytu
COPY --from=jvmtools /opt/saytu/tools/checkstyle /opt/saytu/tools/checkstyle
COPY --from=jvmtools /opt/saytu/tools/pmd /opt/saytu/tools/pmd
COPY --from=eslint /opt/saytu/tools/eslint /opt/saytu/tools/eslint
COPY --from=eslint /opt/saytu/tools/node /opt/saytu/tools/node
COPY --from=scanners . /src/scanners
ENV SAYTU_TOOLS_DIR=/opt/saytu/tools \
    SAYTU_OPENGREP_RUNTIME=/opt/saytu/tools/opengrep-runtime
# Unit tests run here; Testcontainers integration tests (*IT) need Docker and run in CI with `mvn verify`.
ARG SKIP_TESTS=false
RUN --mount=type=cache,target=/root/.m2 mvn -B -pl saytu-app -am package -DskipTests=${SKIP_TESTS}

# ---------- API runtime ----------
FROM eclipse-temurin:21-jre-alpine AS api
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

# ---------- worker runtime ----------
# glibc base: the Opengrep binary is built for manylinux. util-linux (prlimit, setpriv) is part of the base.
# Ubuntu packages: git, PHP CLI (PHP_CodeSniffer), Cppcheck 2.13, Python 3.12 (SQLFluff virtual environment),
# iptables (blocks the network of the scanner accounts, see worker-entrypoint.sh).
FROM eclipse-temurin:21-jre-noble AS worker
LABEL org.opencontainers.image.title="saytu-worker" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/momos95/saytu"
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates php-cli php-xml cppcheck python3 \
      iptables \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 saytu && useradd -u 10001 -g saytu -d /var/lib/saytu -M -s /usr/sbin/nologin saytu
# Extra CA certificates: JVM (Git platform APIs) and system store (git clone, Trivy database download)
COPY --from=ca / /tmp/extra-ca/
RUN set -e; for f in /tmp/extra-ca/*.pem /tmp/extra-ca/*.crt /tmp/extra-ca/*.cer; do \
      [ -f "$f" ] || continue; \
      keytool -importcert -noprompt -cacerts -storepass changeit -alias "extra-$(basename "$f")" -file "$f"; \
      cp "$f" "/usr/local/share/ca-certificates/extra-$(basename "${f%.*}").crt"; \
    done; update-ca-certificates >/dev/null; rm -rf /tmp/extra-ca
COPY --from=tools /opt/saytu /opt/saytu
COPY --from=jvmtools /opt/saytu/tools/checkstyle /opt/saytu/tools/checkstyle
COPY --from=jvmtools /opt/saytu/tools/pmd /opt/saytu/tools/pmd
COPY --from=eslint /opt/saytu/tools/eslint /opt/saytu/tools/eslint
COPY --from=eslint /opt/saytu/tools/node /opt/saytu/tools/node
RUN mkdir -p /var/lib/saytu/work /var/lib/saytu/trivy /etc/saytu/rules/opengrep \
    && chown -R saytu:saytu /var/lib/saytu && chmod 0700 /var/lib/saytu/work
WORKDIR /app
COPY --from=build --chown=saytu:saytu /src/saytu-app/target/saytu.jar app.jar
COPY worker-entrypoint.sh /app/worker-entrypoint.sh
# CRLF from a Windows checkout would break the shebang
RUN sed -i 's/\r$//' /app/worker-entrypoint.sh && chmod 0755 /app/worker-entrypoint.sh
# docker-compose runs the worker as root with a reduced capability set so that each job's scanners get their
# own account (ScannerIsolation); without it the image runs as the unprivileged "saytu" user.
USER 10001:10001
ENV SAYTU_WORKER_ENABLED=true \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=25 -XX:+ExitOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom"
HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=5 \
  CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080 && printf "GET /actuator/health/readiness HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 && grep -q "\"UP\"" <&3'
ENTRYPOINT ["/app/worker-entrypoint.sh"]
