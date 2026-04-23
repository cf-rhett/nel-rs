use super::{find_deepest_text, find_source, Error};

impl From<&reqwest::Error> for Error {
    fn from(err: &reqwest::Error) -> Self {
        // 1. Source-chain based classification. Walk looking for types we
        //    structurally recognise, in priority order:
        //      - hyper::Error: HTTP-layer failures
        //      - rustls::Error: TLS failures from the rustls stack
        //      - std::io::Error: DNS / TCP / generic I/O failures
        //    `find_source` handles both `source()` traversal and
        //    `io::Error::get_ref()` unwrapping at each hop.
        let err_dyn: &(dyn std::error::Error + 'static) = err;
        if let Some(hyper_err) = find_source::<hyper::Error>(err_dyn) {
            return hyper_err.into();
        }
        if let Some(rustls_err) = find_source::<rustls::Error>(err_dyn) {
            return super::rustls_error_to_nel(rustls_err);
        }
        if let Some(io_err) = find_source::<std::io::Error>(err_dyn) {
            return io_err.into();
        }

        // 2. reqwest-level classification helpers. `is_connect()` walks down
        //    into `hyper_util::client::legacy::Error` and still works in
        //    reqwest 0.12 even though `hyper::Error::is_connect()` is gone.
        //    Preserves the `tcp.failed` / `tcp.timed_out` signal that
        //    connector-phase failures would otherwise lose to `unknown`.
        if err.is_timeout() {
            return Error::new("tcp", "timed_out");
        }
        if err.is_connect() {
            return Error::new("tcp", "failed");
        }

        // 3. Native-tls / SecureTransport / schannel fallback. These stacks
        //    don't expose structured error kinds, so we substring-match on
        //    the deepest error in the source chain. Fragile on purpose --
        //    each branch has an offline regression test in the parent
        //    module's test suite and in this module's tests.
        if let Some(text) = find_deepest_text(err_dyn) {
            if let Some(nel) = classify_native_tls_text(&text) {
                return nel;
            }
        }

        Error::new("unknown", "")
    }
}

impl From<&hyper::Error> for Error {
    fn from(err: &hyper::Error) -> Self {
        // If this is caused by an underlying I/O error, delegate to that.
        // The I/O error classifier picks up rustls TLS failures via the
        // nested source chain.
        if let Some(io_err) = find_source::<std::io::Error>(err) {
            return io_err.into();
        }

        if err.is_parse() {
            Error::new("http", "response.invalid")
        } else if err.is_user() {
            Error::new("http", "protocol.error")
        } else if err.is_incomplete_message() {
            Error::new("tcp", "closed")
        } else if err.is_body_write_aborted() {
            Error::new("abandoned", "")
        } else if err.is_timeout() {
            Error::new("tcp", "timed_out")
        } else if err.is_closed() {
            Error::new("tcp", "reset")
        } else if err.is_canceled() {
            Error::new("tcp", "aborted")
        } else {
            Error::new("unknown", "")
        }
    }
}

/// Classify a substring match against the deepest native-tls / schannel /
/// SecureTransport error wording. Table-driven so new wordings land in one
/// place; each needle is covered by an offline test in `mod tests` below.
fn classify_native_tls_text(text: &str) -> Option<Error> {
    // (needles, class, subclass). Needles are matched case-insensitively.
    const TABLE: &[(&[&str], &str, &str)] = &[
        (
            &[
                "hostname mismatch",
                "host name mismatch",
                "not valid for name",
                "cn name is invalid",
            ],
            "tls",
            "cert.name_invalid",
        ),
        (
            &[
                "expired certificate",
                "certificate has expired",
                "certificate is expired",
            ],
            "tls",
            "cert.date_invalid",
        ),
        (
            &[
                "self signed certificate",
                "self-signed certificate",
                "unknown issuer",
                "untrusted root",
                "unable to get local issuer",
            ],
            "tls",
            "cert.authority_invalid",
        ),
    ];

    let lower = text.to_lowercase();
    TABLE
        .iter()
        .find(|(needles, _, _)| needles.iter().any(|n| lower.contains(n)))
        .map(|(_, class, subclass)| Error::new(*class, *subclass))
}

#[cfg(test)]
mod tests {
    use super::{classify_native_tls_text, Error};

    // ---- Offline substring tests for the native-tls fallback. ----

    #[test]
    fn name_invalid_wordings() {
        let cases = [
            // OpenSSL / reqwest wording
            "Hostname mismatch for example.com",
            // SecureTransport (macOS) wording (seen historically)
            "Host name mismatch",
            // schannel-style
            "the CN name is invalid",
            // rustls 0.20-era display (kept for defence-in-depth)
            "certificate not valid for name \"example.com\"",
        ];
        for msg in cases {
            let nel = classify_native_tls_text(msg)
                .unwrap_or_else(|| panic!("{msg:?} should classify as tls.cert.name_invalid"));
            assert_eq!(nel.to_string(), "tls.cert.name_invalid", "for {msg:?}");
        }
    }

    #[test]
    fn date_invalid_wordings() {
        let cases = [
            "certificate has expired",
            "The certificate is expired",
            "found expired certificate in chain",
        ];
        for msg in cases {
            let nel = classify_native_tls_text(msg)
                .unwrap_or_else(|| panic!("{msg:?} should classify as tls.cert.date_invalid"));
            assert_eq!(nel.to_string(), "tls.cert.date_invalid", "for {msg:?}");
        }
    }

    #[test]
    fn authority_invalid_wordings() {
        let cases = [
            "self signed certificate in chain",
            "self-signed certificate",
            "certificate signed by unknown issuer",
            "untrusted root certificate",
            "unable to get local issuer certificate",
        ];
        for msg in cases {
            let nel = classify_native_tls_text(msg)
                .unwrap_or_else(|| panic!("{msg:?} should classify as tls.cert.authority_invalid"));
            assert_eq!(nel.to_string(), "tls.cert.authority_invalid", "for {msg:?}");
        }
    }

    #[test]
    fn non_tls_wordings_do_not_match() {
        let cases = [
            "connection refused",
            "broken pipe",
            "DHCP lease expired",
            "cookie expired",
        ];
        for msg in cases {
            assert!(
                classify_native_tls_text(msg).is_none(),
                "{msg:?} should not match any native-tls classifier"
            );
        }
    }

    // ---- Live-network integration tests. Gated behind `#[ignore]` so they
    // only run when explicitly requested with `cargo test -- --ignored`. ----

    enum TlsBackend {
        Native,
        Rustls,
    }

    impl TlsBackend {
        fn client(&self) -> reqwest::Client {
            match self {
                TlsBackend::Native => reqwest::ClientBuilder::new()
                    .use_native_tls()
                    .build()
                    .expect("native-tls client builds"),
                TlsBackend::Rustls => reqwest::ClientBuilder::new()
                    .use_rustls_tls()
                    .build()
                    .expect("rustls client builds"),
            }
        }
    }

    async fn classify(backend: TlsBackend, url: &str) -> Error {
        let result = backend.client().get(url).send().await;
        match result {
            Ok(_) => panic!("request against {url} unexpectedly succeeded"),
            Err(e) => (&e).into(),
        }
    }

    #[tokio::test]
    #[ignore = "live network: hits badssl.com / NXDOMAIN DNS; run with --ignored"]
    async fn no_dns() {
        for backend in [TlsBackend::Native, TlsBackend::Rustls] {
            let nel = classify(backend, "http://invalid.").await;
            assert_eq!(nel.to_string(), "dns.name_not_resolved");
            assert_eq!(nel.phase(), "dns");
        }
    }

    #[tokio::test]
    #[ignore = "live network: hits badssl.com; run with --ignored"]
    async fn expired_cert() {
        for backend in [TlsBackend::Native, TlsBackend::Rustls] {
            let nel = classify(backend, "https://expired.badssl.com/").await;
            assert_eq!(nel.to_string(), "tls.cert.date_invalid");
            assert_eq!(nel.phase(), "connection");
        }
    }

    #[tokio::test]
    #[ignore = "live network: hits badssl.com; run with --ignored"]
    async fn invalid_name() {
        // The cert at wrong.host.badssl.com is valid for *.badssl.com but
        // served on the wrong SAN. native-tls reports this as a name
        // mismatch directly. rustls (with webpki-roots) may surface it as
        // `UnknownIssuer` instead because its verifier checks the issuer
        // chain against the pinned webpki-roots set first, and badssl.com's
        // issuing CA is not always present in that subset. Accept either
        // classification rather than pinning a per-backend quirk.
        for backend in [TlsBackend::Native, TlsBackend::Rustls] {
            let nel = classify(backend, "https://wrong.host.badssl.com/").await;
            assert!(
                matches!(
                    nel.subclass.as_str(),
                    "cert.name_invalid" | "cert.authority_invalid"
                ),
                "unexpected subclass for wrong.host.badssl.com: {:?}",
                nel.to_string(),
            );
            assert_eq!(nel.class, "tls");
            assert_eq!(nel.phase(), "connection");
        }
    }
}
