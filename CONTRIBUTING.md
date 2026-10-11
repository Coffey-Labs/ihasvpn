# Contributing to ihasvpn

Thanks for your interest. Bug reports, feature requests, code and
documentation are all welcome.

## Before you start

- ihasvpn is one container: the WireGuard server and the UI that manages it.
  Contributions that need a second service (a database, a message queue, a
  separate frontend host) are out of scope.
- The kernel data plane is the point. Anything on the packet path has to
  justify its cost.
- This project is licensed under **AGPL-3.0**. Code you contribute is
  distributed under that licence, including for hosted deployments.

## Development

You need Go (see `go.mod` for the version), Node 26 and Docker.

```sh
# Frontend, with hot reload, proxying /api to a local server on :51821
cd web && npm ci && npm run dev

# Backend against the in-memory mock data plane -- no privileges needed
IHASVPN_BACKEND=mock IHASVPN_DATA_DIR=/tmp/ihasvpn IHASVPN_HTTP_LISTEN=127.0.0.1:51821 go run ./cmd/ihasvpn
```

The mock simulates peers handshaking and moving traffic so the dashboard has
something to show. For the real thing:

```sh
cd web && npm run build && cd ..
docker build -t ihasvpn:dev .
docker run --rm --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
  -p 51820:51820/udp -p 127.0.0.1:51821:51821 -v ihasvpn-dev:/data ihasvpn:dev
```

## Before you commit

CI checks are not a substitute for building locally. Run, in this order:

```sh
cd web && npm run build && cd ..     # type-checks and builds the UI
go vet ./... && go test -count=1 ./...
docker build -t ihasvpn:dev .            # when the change reaches the image
```

`go test` covers the engine against the mock data plane and the whole HTTP
API through `httptest`. A change to the data plane itself (`internal/wg`,
`internal/netcfg`) needs a run in a container with NET_ADMIN and a real
client handshake; say in the pull request that you did that.

## Sending a change

New accounts on git.coffeylabs.org can file issues but can't push or fork.
Until you have repository access, open an
[issue](https://git.coffeylabs.org/coffey-labs/ihasvpn/issues) for the change, or say hello
on [community.coffeylabs.org](https://community.coffeylabs.org), and attach the
change to the issue as a patch:

```sh
git format-patch origin/main --stdout > my-change.patch
```

Repository access goes to volunteers we have worked with; a few good issues or
patches is the usual way in. After that you push a branch here and open a pull
request. The GitHub copy is a read-only mirror, so pull requests opened
there are not merged.

## Pull requests

- One change per pull request, with a description of what and why.
- Keep the commit message about the change. No tooling attributions or
  generated-by footers.
- New settings need a line in the README's configuration table; anything on
  the packet path needs a note in `docs/performance.md`.
