# Changelog

## 0.2.0

### Breaking changes

- **MSRV** is now **1.86** (previously undeclared). Driven by transitive
  dependencies: `rand_core 0.10` requires Cargo's stabilized edition 2024
  (Rust 1.85+) and `icu_provider 2.2` requires rustc 1.86.
- **Edition** bumped from 2018 to 2024.
- **`rustls` 0.21 → 0.23.** `rustls::Error` is named in the public
  `From<&std::io::Error>` impl's classifier, so `rustls`'s major version is
  observable through the library's dependency surface.
- **`hyper` 0.14 → 1.** `From<&hyper::Error>`'s classification changed for
  connection-phase errors: hyper 1 removed `hyper::Error::is_connect()`, and
  the TLS-cert substring checks that depended on it are gone.
- **`reqwest` 0.11 → 0.12.**
- **`rand` 0.8 → 0.10.**
- **`Error` now implements `Display` directly** (previously only `ToString`
  via the blanket impl). Downstream code with a local `impl Display for
  nel::Error` will conflict.
- **Classification output changes.** For the same input error, the returned
  `Error::class` / `Error::subclass` strings have changed in several cases.
  Downstream code that pattern-matches on those strings may need updating:
  - `From<&std::io::Error>` with a nested `rustls::Error` source now
    produces structured TLS subclasses (`cert.name_invalid`,
    `cert.date_invalid`, `cert.authority_invalid`, `cert.revoked`,
    `cert.invalid`) based on the `rustls::CertificateError` variant, rather
    than a uniform `tls.protocol.error`.
  - `From<&reqwest::Error>` now classifies connection-phase failures via
    `reqwest::Error::is_connect()` / `is_timeout()` before falling through
    to `unknown`, so it still produces `tcp.failed` / `tcp.timed_out` for
    the connector-phase cases that hyper 0.14's `is_connect()` used to
    catch.
  - The `io::Error` text fallback in `From<&std::io::Error>` added
    macOS/BSD/Windows DNS wordings (`"nodename nor servname provided"`,
    `"no such host"`), tightened the overly-broad `"expired"` match to
    specific TLS cert-expiry wordings only, and removed rustls-0.21
    `Debug`-form substrings (`"certnotvalidforname"`, `"unknownissuer"`)
    that are now covered structurally.
  - The `unknown` class subclass is now an empty string (was the upstream
    error's `Display`, which leaked reqwest/hyper internal wording into
    the NEL wire format).

### New

- `Error::new(class, subclass)` is now public.
- `rustls::CertificateError::{UnknownRevocationStatus, ExpiredRevocationList,
  ExpiredRevocationListContext}` classify as `tls.cert.revoked` (closest NEL
  subclass for "revocation status unknown").
- `examples/reqwest.rs` — minimal end-to-end integration example.
- Offline regression tests for every substring branch in the TLS / DNS text
  fallbacks, so fragile-on-purpose wording matches rot detectably under CI
  rather than only under live-network testing.

### Removed

- `examples/hyper.rs` — the hyper 1 migration required enough HTTP-level
  plumbing in the example to obscure the NEL-relevant code. Integration
  against hyper directly is still possible (the `From<&hyper::Error>` impl
  remains), but the canonical example now uses reqwest.
- `lazy_static` dependency (replaced by `std::sync::LazyLock`).
