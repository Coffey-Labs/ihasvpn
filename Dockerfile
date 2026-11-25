# ---- web build ----
# Docker Hub's official images, pulled through Google's mirror: GitHub's
# shared runners hit Docker Hub's anonymous pull limit (429), which the
# mirror is not subject to. Same images, same digests (checked 2026-10-09).
FROM mirror.gcr.io/library/node:26-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- go build ----
FROM mirror.gcr.io/library/golang:1.27-alpine AS build
# The version string the binary reports. Worked out by whoever runs the
# build (CI passes the tag); left empty it says "dev".
ARG IHASVPN_VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=web /src/internal/server/static/dist internal/server/static/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/Coffey-Labs/ihasvpn/internal/engine.Version=${IHASVPN_VERSION}" -o /ihasvpn ./cmd/ihasvpn

# ---- runtime ----
FROM mirror.gcr.io/library/alpine:3.22
# nftables does the NAT; wireguard-go is the fallback data plane for hosts
# without the kernel module; wireguard-tools gives `wg show` for debugging.
RUN apk add --no-cache nftables wireguard-go wireguard-tools ca-certificates tzdata \
    && mkdir -p /data
COPY --from=build /ihasvpn /usr/local/bin/ihasvpn
ENV IHASVPN_DATA_DIR=/data \
    IHASVPN_HTTP_LISTEN=:51821
VOLUME ["/data"]
EXPOSE 51820/udp 51821/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD wget -qO- http://127.0.0.1:51821/api/health || exit 1
ENTRYPOINT ["ihasvpn"]

# Last in the image, after everything that does work: a value that changes
# every build (the version, the commit) then never costs a cached layer.
# Re-declared: an ARG does not cross stages. For the labels.
ARG IHASVPN_VERSION=dev
ARG IHASVPN_REVISION=""
# What the image says it is, for registries and anyone inspecting it.
LABEL org.opencontainers.image.title="ihasvpn" \
      org.opencontainers.image.description="A self-hosted WireGuard server with a secure web console, in one container." \
      org.opencontainers.image.url="https://ihasvpn.org/" \
      org.opencontainers.image.source="https://git.coffeylabs.org/coffey-labs/ihasvpn" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="Coffey Labs LLC" \
      org.opencontainers.image.version="$IHASVPN_VERSION" \
      org.opencontainers.image.revision="$IHASVPN_REVISION"
