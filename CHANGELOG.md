# Changelog


## [4.4.X] - 2026-07-22

### Added

- **SIV-1244**: Dual-signature session-hijack detection. In addition to the legacy IP-based
  `.client.signature`, the middleware now writes and validates a new `.client.signatureV2`
  computed as `SHA1(User-Agent + COOKIE_SECRET)` — deliberately excluding the client IP,
  which is unstable across CHS services behind different infrastructure paths and was causing
  false hijack detections on cross-service journeys (e.g. `identity-verification-web` →
  `acsp-manage-users-web`).

### Changed

- Session validation now prefers `.client.signatureV2` when present; otherwise it validates
  the legacy `.client.signature` and opportunistically backfills `.client.signatureV2` for
  future requests. On first sign-in both signatures are written. On a possible hijack both
  signatures are cleared. Structured logs distinguish `signature_version` and `fallback_used`.
- The legacy IP-based `.client.signature` is retained unchanged so services still running
  older library versions continue to work during the (uncoordinated) rollout.


## [4.4.23] - 2026-07-01

### Security

- **SIV-1222**: Fixed IP extraction in session-hijack detection (`getClientIp`). The function now uses the rightmost public IP from the `X-Forwarded-For` header, consistent with `web-security-java`'s `HijackFilter`. Previously the leftmost IP was used, which could be spoofed by a client prepending a fabricated IP to the header.

### Changed

- `getClientIp` now recognises IPv6 private addresses (`::1`, `::ffff:` IPv4-mapped, `fe80::/10` link-local, `fc00::/7` unique local) as well as RFC 1918 IPv4 ranges.
- `getClientIp` now falls back to `X-REAL-IP` header before `socket.remoteAddress` when `X-Forwarded-For` is absent, matching `web-security-java`'s fallback chain.
- Absent `User-Agent` header now contributes `""` to the signature hash (previously coerced to the string `"undefined"`), matching `web-security-java`'s `getUserAgent()` null handling.
- Empty/whitespace-only entries in `X-Forwarded-For` are filtered out before processing.

### Migration note

All active signed-in user sessions will be invalidated on the first request after a consuming service upgrades to this version. The stored session signature was computed using the old (leftmost) IP; it will not match the new (rightmost public) IP, triggering a re-authentication redirect.

**Action required for consuming service teams:** plan the upgrade to coincide with a low-traffic window, or communicate to users that a one-time sign-in will be required.

Affected services are listed in SIV-1222.
