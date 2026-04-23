Network Error Logging
---------------------

This crate implements basic Rust utilities for building NEL reports from network
errors, and queueing those reports for submission in the background.

The NEL specification can be found [here](https://www.w3.org/TR/network-error-logging/).

## Usage

The `reqwest-error` feature (on by default) provides `From<&reqwest::Error>`
and `From<&hyper::Error>` impls that classify common network failures into
NEL error type strings (`dns.name_not_resolved`, `tcp.failed`,
`tls.cert.date_invalid`, etc.).

See `examples/reqwest.rs` for a minimal end-to-end integration that spawns
`handle_reports`, captures `NEL` and `Report-To` response headers, and
classifies request failures.

## MSRV

Minimum supported Rust version is **1.86** (driven by transitive deps:
`rand_core 0.10` needs edition 2024, `icu_provider 2.2` needs rustc 1.86).

## Features

- `reqwest-error` (default): enable the `From<&reqwest::Error>` and
  `From<&hyper::Error>` classifiers. Adds `reqwest` and `hyper` as
  dependencies.

The crate also always depends on `rustls` for typed classification of TLS
certificate errors via `rustls::CertificateError`. We depend on rustls for
its error types only; we never run a handshake, so no runtime cost is paid
when rustls isn't your active TLS backend.

## TLS backend and crypto provider selection

This crate deliberately does **not** pick a TLS backend for `reqwest` or a
crypto provider for `rustls`. Those choices belong to the binary that
consumes `nel`:

- **`reqwest` is pulled with `default-features = false` and no TLS feature.**
  If your binary uses `reqwest` over HTTPS, you must enable `rustls-tls`
  (or `rustls-tls-native-roots`, `native-tls`, etc.) on your own `reqwest`
  dependency. If you don't, reqwest will fail at runtime on the first HTTPS
  request.
- **`rustls` is pulled with `default-features = false` and no crypto
  provider feature.** We only name `rustls::Error` / `CertificateError` for
  classification; we never run the crypto. Your downstream TLS client
  (`rustls-tls` in reqwest, for example) picks `ring` or `aws-lc-rs` via
  its own features. Do not enable a crypto-provider feature here — it
  would force a provider into every downstream build.
