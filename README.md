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

Minimum supported Rust version is **1.80** (for `std::sync::LazyLock`).

## Features

- `reqwest-error` (default): enable the `From<&reqwest::Error>` and
  `From<&hyper::Error>` classifiers. Adds `reqwest` and `hyper` as
  dependencies.

The crate also always depends on `rustls` (for typed classification of TLS
certificate errors via `rustls::CertificateError`), even when the reqwest
feature is off, because the io::Error classifier walks rustls error sources
regardless of how the HTTP client is configured.
