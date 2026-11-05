# syntax=docker/dockerfile:1
# SAYTU web UI. Build context: ./frontend

# ---------- build ----------
FROM node:22-alpine AS build
WORKDIR /src
# Extra CA certificates (build context "ca" = ./data/ca) so that npm works behind an HTTPS inspection proxy
COPY --from=ca / /tmp/extra-ca/
RUN cat /tmp/extra-ca/*.pem /tmp/extra-ca/*.crt /tmp/extra-ca/*.cer 2>/dev/null > /etc/ssl/extra-ca.pem; \
    if [ -s /etc/ssl/extra-ca.pem ]; then echo "extra CA certificates: $(grep -c 'BEGIN CERTIFICATE' /etc/ssl/extra-ca.pem)"; \
    else echo "# none" > /etc/ssl/extra-ca.pem; fi
COPY package.json package-lock.json* ./
# Reproducible install when the lockfile is committed (recommended); plain install otherwise.
RUN --mount=type=cache,target=/root/.npm \
    if grep -q 'BEGIN CERTIFICATE' /etc/ssl/extra-ca.pem; then export NODE_EXTRA_CA_CERTS=/etc/ssl/extra-ca.pem; fi; \
    if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
COPY . .
RUN npx ng build --configuration production

# ---------- runtime ----------
FROM nginxinc/nginx-unprivileged:1.28-alpine AS runtime
LABEL org.opencontainers.image.title="saytu-web" \
      org.opencontainers.image.licenses="Apache-2.0"
# Only these variables are substituted in the template, nginx's own $variables are left intact
ENV NGINX_ENVSUBST_FILTER="^SAYTU_"
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY --chmod=755 nginx/10-keycloak-origin.envsh /docker-entrypoint.d/10-keycloak-origin.envsh
# A Windows checkout may have converted these files to CRLF: "export NAME\r" makes the entrypoint exit (code 2)
USER root
RUN sed -i 's/\r$//' /docker-entrypoint.d/10-keycloak-origin.envsh /etc/nginx/templates/default.conf.template
COPY --from=build /src/dist/saytu-web/browser /usr/share/nginx/html
# public/assets/config.json (dev fallback) is shadowed by the exact-match location generated from the environment
EXPOSE 8080
USER 101
