# Security Policy

## Supported versions

Security fixes go to `main` and the next release. Older releases are not
patched.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Email
**securityATcoffeylabsDOTorg** with what you found, how to reproduce it and what
you think the impact is. You will get an acknowledgement within a few days
and a fix or a plan before anything is made public.

## What ihasvpn does to protect itself

- The admin UI requires a password (argon2id, 64 MiB, 3 passes) and offers
  time-based one-time codes with recovery codes. Sessions are random 256-bit
  tokens stored hashed, `HttpOnly`, `SameSite=Strict`, with idle and absolute
  expiry.
- Every state-changing request must come from the same origin
  (`Sec-Fetch-Site` / `Origin` are checked in addition to the cookie policy)
  and carry a JSON body; the first-run setup endpoint stops working the
  moment a user exists.
- Login is rate-limited per address and per username, and a failed login for
  an unknown user takes as long as one for a known user.
- Responses carry a strict Content-Security-Policy, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` and, under TLS, HSTS.
- Peer private keys never appear in list or detail responses; they are only
  returned through the configuration and QR endpoints, and each view is
  written to the audit log. The server's own private key never leaves the
  process.
- The database file is created mode 0600 and the container image contains
  no shell tooling beyond what nftables and WireGuard need.

## What you must do

- Do not expose port 51821 to the internet without TLS. Either set
  `IHASVPN_TLS_SELF_SIGNED=true` (or `IHASVPN_TLS_CERT`/`IHASVPN_TLS_KEY`) or put a
  TLS-terminating reverse proxy in front and list it in
  `IHASVPN_TRUSTED_PROXIES` so client addresses in the audit log are right.
- Turn on two-factor authentication for every administrator.
- Keep the `/data` volume private: it holds every peer's private key.
