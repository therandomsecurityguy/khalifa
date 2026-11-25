FROM cgr.dev/chainguard/node:latest-dev@sha256:8e8d45dd674724ccc71aed270223c3e2efc74edde6c841158d618d2baaaf5527 AS dependencies

USER root
WORKDIR /workspace
ENV NODE_ENV=development

RUN test "$(node --version)" = "v26.13.1" && npm install --global --ignore-scripts --no-audit --no-fund npm@11.19.1 && test "$(/usr/local/bin/npm --version)" = "11.19.1"

COPY package.json package-lock.json ./
COPY api-service/package.json ./api-service/
COPY cdk/package.json ./cdk/
COPY packages/integrations/package.json ./packages/integrations/
COPY packages/risk-engine/package.json ./packages/risk-engine/
COPY packages/mcp-server/package.json ./packages/mcp-server/
COPY ui/package.json ./ui/
COPY lambdas/cloudtrail-analyzer/package.json ./lambdas/cloudtrail-analyzer/
COPY lambdas/collector/package.json ./lambdas/collector/
COPY lambdas/dspm-scanner/package.json ./lambdas/dspm-scanner/
COPY lambdas/graph-writer/package.json ./lambdas/graph-writer/
COPY lambdas/incremental-collector/package.json ./lambdas/incremental-collector/
COPY lambdas/least-privilege-sweep/package.json ./lambdas/least-privilege-sweep/
COPY lambdas/list-accounts/package.json ./lambdas/list-accounts/
COPY lambdas/policy-evaluator/package.json ./lambdas/policy-evaluator/
COPY lambdas/runtime/package.json ./lambdas/runtime/
COPY lambdas/shared/package.json ./lambdas/shared/
RUN --mount=type=cache,target=/root/.npm /usr/local/bin/npm ci
COPY . .

FROM dependencies AS api-build

RUN /usr/local/bin/npm run build:api

FROM dependencies AS ui-build

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
RUN /usr/local/bin/npm run build:ui

FROM dependencies AS rule-runner-build

RUN /usr/local/bin/npm run build:packages && /usr/local/bin/npm run build -w lambdas/runtime

FROM cgr.dev/chainguard/node:latest@sha256:3fb5318a58807dec0f2ece547efbe8d62c67b7b2fd91a16795b98651d6385dbe AS runtime

# Build identity, set by the release workflow's build args. The API reports it
# through /version and the khalifa_build_info metric; targets that do not read
# it receive the variables harmlessly.
ARG BUILD_VERSION=dev
ARG BUILD_SHA=
ENV KHALIFA_VERSION=${BUILD_VERSION}
ENV KHALIFA_SHA=${BUILD_SHA}

ENV NODE_ENV=production
USER 65532

FROM runtime AS api

WORKDIR /app
COPY --from=api-build --chown=65532:65532 /workspace/api-service/dist/server.js ./
COPY --from=api-build --chown=65532:65532 /workspace/api-service/dist/server.js.map ./

ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:8080/livez').then(r=>{if(!r.ok)throw new Error(String(r.status))})"]
CMD ["--enable-source-maps", "server.js"]

FROM runtime AS ui

WORKDIR /app
COPY --from=ui-build --chown=65532:65532 /workspace/ui/.next/standalone ./
COPY --from=ui-build --chown=65532:65532 /workspace/ui/.next/static ./ui/.next/static
COPY --from=ui-build --chown=65532:65532 /workspace/ui/public ./ui/public

WORKDIR /app/ui
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
ENV NEXT_TELEMETRY_DISABLED=1
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:3000/healthz').then(r=>{if(!r.ok)throw new Error(String(r.status))})"]
CMD ["server.js"]

FROM runtime AS rule-runner

WORKDIR /app
COPY --from=rule-runner-build --chown=65532:65532 /workspace/lambdas/runtime/dist/index.js ./runtime.js
COPY --from=rule-runner-build --chown=65532:65532 /workspace/lambdas/runtime/dist/index.js.map ./runtime.js.map

ENTRYPOINT ["/usr/bin/node", "--enable-source-maps", "/app/runtime.js"]
CMD ["risk"]
