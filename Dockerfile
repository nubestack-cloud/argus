# Single multi-entrypoint hub image (ADR-7) — one image, dispatched by subcommand
# (migrate | api | orchestrator | gitops | notify), not one image per service.
# Distroless, non-root, read-only root filesystem (lld/12-deployment-design.md §2,
# HLD §20.1's supply-chain posture).

# Builds the web UI's static assets, embedded into the hub binary below via
# go:embed (internal/api/static.go) — this is what makes the end product one
# container (hub + Postgres) instead of hub + a separate UI container, per
# DESIGN.md §4.1.1's consolidation decision.
#
# --platform=$BUILDPLATFORM on this stage and the Go build stage below is what
# makes `docker buildx build --platform linux/amd64,linux/arm64 .` produce a
# real multi-arch image WITHOUT QEMU emulating the compute-heavy parts (npm
# build, go build): both stages run natively on the machine doing the build,
# and the Go stage cross-compiles for the requested TARGETARCH instead of
# being emulated as that arch. Only the tiny final COPY-only stages below
# actually pull an arch-specific base layer, and copying a file needs no
# emulation. Buildx sets BUILDPLATFORM/TARGETPLATFORM/TARGETARCH automatically
# from --platform; no flag on this file's own invocation is required. The web
# build's output is HTML/JS/CSS, so it is identical regardless of target arch —
# building it once per BUILDPLATFORM rather than once per TARGETPLATFORM is a
# real speedup, not just a correctness nicety.
FROM --platform=$BUILDPLATFORM node:22-bookworm AS web-build
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# The Go source + module cache, shared by every Go build stage below.
#
# Split out from `build` so the AGENT can be built without the web UI. The
# agent binary does not embed the UI at all (go:embed on internal/api/static
# is the hub's, not cmd/agent's), but while hub and agent were compiled in one
# stage whose first act was `COPY --from=web-build`, `docker build --target
# agent` could not start until `npm run build` had succeeded. A frontend that
# does not typecheck therefore blocked building a cluster agent — which is not
# a dependency that exists in the code, only one that existed in this file.
FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm AS gosrc
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/

# Spoke agent binary (cmd/agent). No web assets, no VERSION ldflag —
# internal/buildinfo falls back to Go's embedded VCS stamp, and the agent
# reports its version over the tunnel from tunnel.AgentBuildVersion, not from
# a build arg.
FROM gosrc AS agent-build
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -o /out/agent ./cmd/agent

FROM gosrc AS build
# Overwrite internal/api/static/'s checked-in placeholder (see static.go's
# comment — it exists only so `go build` works without Docker) with the real
# built UI before compiling, so go:embed picks up the real assets.
RUN rm -rf internal/api/static
COPY --from=web-build /web/dist internal/api/static
# The build's own version, printed by the sign-in screens and served by
# GET /api/v1/auth/sso/providers. EMPTY by default, not a plausible-looking tag:
# internal/buildinfo falls back to Go's embedded VCS stamp and then to "dev", so
# an unstamped build reports "dev" rather than claiming a version it isn't.
#
# DO NOT `docker build` this by hand — use ./scripts/build-images.sh, which
# computes the version from `git describe` and passes it. A plain `docker build`
# still succeeds and still ships; the login page just reports "dev", which is
# the kind of thing nobody notices until they need to identify a running image.
ARG VERSION=
# TARGETOS/TARGETARCH are buildx's automatic platform-args (empty, and both
# go build flags below inert, on a plain non-buildx `docker build` — that
# still produces a single native image exactly as before this comment was
# added). Cross-compiling here rather than emulating is what lets this whole
# stage run at native (BUILDPLATFORM) speed for every target arch in one
# `--platform` build.
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -ldflags "-X argus/internal/buildinfo.version=${VERSION}" -o /out/hub ./cmd/hub
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -o /out/cli-runner ./cmd/cli-runner

# "static" distroless has no libc/NSS/DNS config machinery at all, which turned out
# to break container-name DNS resolution in this environment even though the built
# binary is CGO_ENABLED=0 (verified empirically — see STATUS.md's Phase 0 notes).
# "base-debian12" keeps distroless/non-root/no-shell but includes glibc, which is
# what actually resolves the compose network's service names correctly.

# Spoke agent image (cmd/agent) — built from the same source, but not the
# default target: `docker build .` with no --target still produces the hub
# image below, unchanged from before this stage was added. Build this one
# explicitly with `docker build --target agent -t argus/agent:dev .`.
#
# This target does NOT build the web UI or the hub binary (see the gosrc/
# agent-build stages above): an agent image is buildable from a tree whose
# frontend does not currently typecheck, which is the normal state of a repo
# mid-change and used to block it.
FROM gcr.io/distroless/base-debian12:nonroot AS agent
COPY --from=agent-build /out/agent /usr/local/bin/agent
# ARGUS's licence and the licences of everything built into it travel with the binary.
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/agent"]

# CLI-agent runner image (cmd/cli-runner) — lld/12-deployment-design.md §12.
# Not the default target: `docker build .` still produces the hub image above,
# byte-identical to before this stage existed.
#
#   docker build --target cli-runner -t argus/cli-runner:dev .
#
# This is the ONE image in this repo that is deliberately not distroless, and
# §12.1 is the argument for why that's acceptable *here* and not in the hub:
# a coding-agent CLI is a Node application needing a real runtime, a writable
# HOME and a shell, and the whole point of putting it in its own container is
# that this dependency tree ends up somewhere that holds no database
# credential, no agent mTLS material and no plan-signing key (SR-23).
#
# node:22-trixie-slim (Debian 13) rather than the full node image: still Debian (so the
# CLIs' own postinstall steps behave), a few hundred MB rather than ~1GB.
#
# Deliberately NOT --platform=$BUILDPLATFORM, unlike the two stages above: the
# `npm install -g` below runs each CLI's own postinstall script, which fetches
# or selects a platform-specific native binary and has to observe the REAL
# target arch to pick the right one — cross-compiling this stage the way Go is
# cross-compiled above isn't possible, since npm has no equivalent of GOARCH.
# So a multi-arch build of this one stage genuinely runs (not just copies) the
# arm64 image under emulation when built on an amd64 host — slower, and it is
# the one target where this repo cannot currently prove a from-scratch arm64
# build without either a real arm64 runner or QEMU registered on the build
# host (`docker/setup-qemu-action` in CI; see .github/workflows/release.yml).
# Pinned, vendored at build time, never installed at container start
# (§12.4). An unpinned CLI is an unversioned dependency in the middle of the
# investigation loop, and a runtime `npm install` would break airgapped
# installs outright. Override at build time to move the pin:
#   --build-arg CLAUDE_CLI_VERSION=x.y.z
#   --build-arg CODEX_CLI_VERSION=x.y.z
#
# Installed on the BUILD platform and copied into the target image, so a
# multi-arch build needs no emulation: npm is told the target CPU (--cpu) and
# picks that architecture's native binaries, and the final stage runs nothing.
# Installing them in the target stage made the arm64 image need QEMU, which is
# why it used to be amd64-only.
FROM --platform=$BUILDPLATFORM node:22-trixie-slim AS cli-runner-tools
ARG TARGETARCH
ARG CLAUDE_CLI_VERSION=2.0.1
ARG CODEX_CLI_VERSION=0.154.0
RUN set -eu; cpu="$(case "${TARGETARCH:-amd64}" in amd64) echo x64;; *) echo "${TARGETARCH}";; esac)"; \
    npm install -g --prefix /opt/argus-cli --cpu="$cpu" --os=linux --no-fund --no-audit \
      "@anthropic-ai/claude-code@${CLAUDE_CLI_VERSION}" \
      "@openai/codex@${CODEX_CLI_VERSION}" \
    && npm cache clean --force

FROM node:22-trixie-slim AS cli-runner

COPY --from=cli-runner-tools /opt/argus-cli /opt/argus-cli
ENV PATH=/opt/argus-cli/bin:$PATH
COPY --from=build /out/cli-runner /usr/local/bin/cli-runner
# ARGUS's licence and the licences of everything built into it travel with the binary.
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/

# Runs as node:node (uid 1000), not root — the CLI has no need for root, and
# T21 assumes this process will eventually be the one that gets talked into
# something it shouldn't do.
#
# HOME is set per-invocation by the runner itself to a fresh temp directory
# (see cmd/cli-runner's runInvestigation), so no writable HOME is baked in
# here; the container only needs /tmp writable, which an emptyDir provides.
USER node:node
ENV ARGUS_CLI_RUNNER_ADDR=:8090
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/cli-runner"]

# The hub image is deliberately the LAST stage in this file, because
# `docker build .` with no --target builds the last one — that is what makes
# "the default target is still the hub" true rather than aspirational. Adding
# a new stage after this point silently changes what a bare `docker build .`
# produces, which is exactly the mistake that broke compose once (a bare build
# tagged as argus/hub:dev came out as the cli-runner image, and hub-migrate
# then tried to run the runner binary). New stages go ABOVE this comment.
FROM gcr.io/distroless/base-debian12:nonroot AS hub
COPY --from=build /out/hub /usr/local/bin/hub
# ARGUS's licence and the licences of everything built into it travel with the binary.
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/hub"]
