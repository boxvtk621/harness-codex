FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/ internal/
COPY adapters/ adapters/
COPY api/ api/
COPY runtime/ runtime/
COPY cmd/ cmd/
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags='-buildid= -s -w' -o /harness-node ./cmd/harness-node \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags='-buildid= -s -w' -o /harness-tool-runner ./cmd/harness-tool-runner

FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d
WORKDIR /opt/codex
COPY adapters/codex/runtime/package.json adapters/codex/runtime/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund \
    && test "$(./node_modules/.bin/codex --version)" = "codex-cli 0.153.4"
COPY --from=build /harness-node /harness-node
COPY --from=build --chown=0:0 --chmod=0555 /harness-tool-runner /harness-tool-runner
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/boxvtk621/harness-codex" \
      org.opencontainers.image.version="$VERSION" org.opencontainers.image.revision="$REVISION" \
      ru.h1-cloud.component="codex"
ENV PATH=/opt/codex/node_modules/.bin:/usr/local/bin:/usr/bin:/bin
USER 10001:10001
ENTRYPOINT ["/harness-node"]
CMD ["--config", "/config/node.json"]
