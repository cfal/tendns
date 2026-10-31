# Test Coverage

Run the suite without public DNS or HTTPS dependencies:

```sh
CARGO_BUILD_JOBS=1 cargo test --all-targets
CARGO_BUILD_JOBS=1 cargo test --all-targets -- --test-threads=1
CARGO_BUILD_JOBS=1 cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Coverage Map

- Unit tests in `src/protocol.rs`: wire regression vector, authenticated round trips,
  wrong keys/AAD/owners, tampering, malformed plaintext, truncation of all entry
  types, exact size/count/label limits, and timestamp boundaries.
- Unit tests in `src/config.rs` and `src/names.rs`: domain matching, configuration
  validation, upstream restrictions, DNS-name canonicalization, and redacted errors.
- `cli.rs`: offline TXT generation, repeated flags, aliases, validity, distinct
  domain/subdomain keys, invalid arguments, and config-independent key generation.
- `resolution.rs`: hidden-label precedence, no-fallback failure behavior, TXT
  record boundaries/filtering, record-type semantics, CNAME limits, and hex names.
- `resolution/cache.rs`: paused-clock TTL tests, actual overlapping fetches,
  cancellation, eviction, recovery, and expiry while a CNAME lookup is pending.
- `request_policy.rs`: unsupported requests, TSIG refusal, flags, and EDNS limits.
- `transport.rs` and `transport/doh.rs`: UDP/TCP framing and truncation, failover,
  TCP reconnection, DoH certificate/hostname and response checks, request deadlines,
  overload recovery, and encrypted discovery through real local DNS listeners.
- `process.rs` (Unix): generate a key and TXT with the CLI, resolve through the
  actual server process, shut down with SIGTERM, and clean up partial bind failures.

Network fixtures use ephemeral ports. Bound reads and fixture joins turn broken
transport behavior into failures rather than indefinite waits. DoH worker panics
are propagated to the test, including in tests that expect client-side errors.
The nonce non-repetition test is a smoke check, not proof of RNG security.

## Remaining Gaps

This is behavioral coverage, not a measured statement/branch coverage report or a
cryptographic audit. Remaining work includes sustained load and resource-exhaustion
testing, coverage-guided DNS/TXT fuzzing, independent td1 interoperability vectors,
IPv6 socket and cross-platform lifecycle coverage, and dedicated HTTP/2 idle-close,
reconnection, and multi-bootstrap failure scenarios. Local fixtures do not model
real DNS-provider caching, WAN loss, or clock synchronization failures exhaustively.
