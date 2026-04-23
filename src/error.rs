#[cfg(feature = "reqwest-error")]
mod reqwest;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Error {
    pub class: String,
    pub subclass: String,
}

impl Error {
    pub fn new<C, S>(class: C, subclass: S) -> Error
    where
        C: std::fmt::Display,
        S: std::fmt::Display,
    {
        Error {
            class: class.to_string(),
            subclass: subclass.to_string(),
        }
    }

    pub fn phase(&self) -> String {
        match self.class.as_ref() {
            "dns" => "dns",
            "tcp" => "connection",
            "udp" => "connection",
            "tls" => "connection",
            "http" => "application",
            "abandoned" => "application",
            _ => "unknown",
        }
        .to_string()
    }
}

impl ToString for Error {
    fn to_string(&self) -> String {
        if self.class == "unknown" {
            "unknown".to_string()
        } else if self.class == "abandoned" {
            "abandoned".to_string()
        } else {
            format!("{}.{}", self.class, self.subclass)
        }
    }
}

impl From<&std::io::Error> for Error {
    fn from(err: &std::io::Error) -> Self {
        use std::io::ErrorKind;

        match err.kind() {
            ErrorKind::TimedOut => Error::new("tcp", "timed_out"),
            ErrorKind::ConnectionReset => Error::new("tcp", "reset"),
            ErrorKind::ConnectionRefused => Error::new("tcp", "refused"),
            ErrorKind::ConnectionAborted => Error::new("tcp", "aborted"),

            _ => {
                // Inspect the inner error first: rustls surfaces TLS failures
                // through `io::Error::get_ref()` (and sometimes through nested
                // `io::Error` layers that reqwest / hyper-util add). The generic
                // source-chain walker in `find_source` handles both cases.
                if let Some(rustls_err) = find_source::<rustls::Error>(err) {
                    return rustls_error_to_nel(rustls_err);
                }

                if let Some(nel) = classify_io_error_text(&err.to_string()) {
                    return nel;
                }

                // No inner error we recognise and no text match: the kernel
                // gave us some other connection failure (e.g. EHOSTUNREACH
                // without a matching ErrorKind). If there's no inner error at
                // all, attribute to TCP; otherwise we genuinely don't know.
                match err.get_ref() {
                    None => Error::new("tcp", "failed"),
                    Some(_) => Error::new("unknown", ""),
                }
            }
        }
    }
}

/// Classify a lowercased `io::Error` display string into a NEL `Error`.
///
/// This is the fragile-on-purpose fallback for connector-surfaced failures
/// whose error types aren't ones we structurally recognise (native-tls on
/// macOS/Windows, platform DNS wordings, etc.). Each branch is exercised by
/// an offline unit test in `mod tests` below.
fn classify_io_error_text(msg: &str) -> Option<Error> {
    let lower = msg.to_lowercase();

    // DNS resolution failures. Wording varies by platform:
    // - glibc / musl on Linux: "Name or service not known"
    // - libc on macOS+BSD: "nodename nor servname provided, or not known"
    // - Windows: "no such host is known"
    // - Generic / reqwest wording: "no address"
    if lower.contains("no address")
        || lower.contains("name or service not known")
        || lower.contains("nodename nor servname provided")
        || lower.contains("no such host")
    {
        return Some(Error::new("dns", "name_not_resolved"));
    }

    if lower.contains("no route to host") || lower.contains("unreachable") {
        return Some(Error::new("tcp", "address_unreachable"));
    }

    // Native-tls / OpenSSL / SecureTransport cert-expiry wordings. The bare
    // "expired" match from earlier versions was too broad (session/cookie/
    // lease expiry all matched).
    if lower.contains("certificate has expired")
        || lower.contains("certificate is expired")
        || lower.contains("expired certificate")
    {
        return Some(Error::new("tls", "cert.date_invalid"));
    }

    None
}

/// Walk `err`'s source chain (including `io::Error::get_ref` unwrapping at
/// each hop) and return the first ancestor of type `T`, if any.
///
/// This covers both shapes we see in practice:
/// - `io::Error(kind, inner_io::Error(..., T))` — `io::Error` hides its inner
///   via `get_ref()`, not `source()`.
/// - `ConnectError { source: BoxError }` where `source()` surfaces the next
///   layer.
fn find_source<'a, T: std::error::Error + 'static>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a T> {
    let mut cur: Option<&'a (dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(t) = e.downcast_ref::<T>() {
            return Some(t);
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io.get_ref() {
                if let Some(t) = inner.downcast_ref::<T>() {
                    return Some(t);
                }
                // Continue the walk from the io::Error's inner, since
                // `io::Error::source()` does not expose it.
                cur = Some(inner);
                continue;
            }
        }
        cur = e.source();
    }
    None
}

/// Walk `err`'s source chain and return the `to_string()` of the deepest
/// error in the chain. Used as the input to `classify_native_tls_text` when
/// we're given an opaque native-tls-shaped error that doesn't wrap any
/// type we structurally recognise.
#[cfg(feature = "reqwest-error")]
pub(crate) fn find_deepest_text(err: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cur = err.source()?;
    loop {
        match cur.source() {
            Some(next) => cur = next,
            None => return Some(cur.to_string()),
        }
    }
}

fn rustls_error_to_nel(err: &rustls::Error) -> Error {
    use rustls::{CertificateError, Error as RustlsError};

    match err {
        RustlsError::InvalidCertificate(cert_err) => {
            let subclass = match cert_err {
                CertificateError::NotValidForName
                | CertificateError::NotValidForNameContext { .. } => "cert.name_invalid",

                CertificateError::Expired
                | CertificateError::ExpiredContext { .. }
                | CertificateError::NotValidYet
                | CertificateError::NotValidYetContext { .. } => "cert.date_invalid",

                CertificateError::UnknownIssuer => "cert.authority_invalid",

                // Revocation-adjacent: the cert itself may be fine but we
                // can't confirm its revocation status. `cert.revoked` is the
                // closest NEL subclass operators will already be alerting on.
                CertificateError::Revoked
                | CertificateError::UnknownRevocationStatus
                | CertificateError::ExpiredRevocationList
                | CertificateError::ExpiredRevocationListContext { .. } => "cert.revoked",

                // Variants we deliberately fold into `cert.invalid`.
                // `CertificateError` is `#[non_exhaustive]`; the `other` arm
                // below logs any future variant so we notice the drift on a
                // rustls minor bump rather than silently misclassifying.
                CertificateError::BadEncoding
                | CertificateError::BadSignature
                | CertificateError::UnsupportedSignatureAlgorithmContext { .. }
                | CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. }
                | CertificateError::InvalidPurpose
                | CertificateError::InvalidPurposeContext { .. }
                | CertificateError::UnhandledCriticalExtension
                | CertificateError::ApplicationVerificationFailure
                | CertificateError::InvalidOcspResponse
                | CertificateError::Other(_) => "cert.invalid",

                // rustls 0.23's webpki verifier still emits the deprecated
                // bare variant (see rustls src/webpki/mod.rs). Name it
                // explicitly so the drift-logging `other` arm doesn't fire
                // on a known variant.
                #[allow(deprecated)]
                CertificateError::UnsupportedSignatureAlgorithm => "cert.invalid",

                other => {
                    log_unclassified_rustls_variant("CertificateError", other);
                    "cert.invalid"
                }
            };
            Error::new("tls", subclass)
        }
        // Top-level CRL errors (distinct from `InvalidCertificate`'s revocation
        // variants) — rustls' webpki verifier emits these directly when the CRL
        // itself is malformed or can't be validated. We can't confirm the cert's
        // revocation status, so bucket with the other revocation-adjacent cases.
        RustlsError::InvalidCertRevocationList(_) => Error::new("tls", "cert.revoked"),
        // Non-certificate rustls errors: protocol-level failures, no-matching
        // cipher, handshake issues. `rustls::Error` is also `#[non_exhaustive]`,
        // so any variant we don't explicitly name falls through here.
        _ => Error::new("tls", "protocol.error"),
    }
}

fn log_unclassified_rustls_variant<V: std::fmt::Debug>(ty: &str, variant: V) {
    // This path fires only when rustls adds a new `CertificateError` variant
    // our match doesn't cover. Keep the output observable (eprintln rather
    // than tracing so the warning shows up in test runs without needing a
    // subscriber) but non-fatal.
    eprintln!("nel: unclassified rustls {ty} variant {variant:?} — defaulting to cert.invalid");
}

#[cfg(test)]
mod tests {
    use super::{Error, classify_io_error_text, rustls_error_to_nel};
    use rustls::{CertificateError, Error as RustlsError};

    #[test]
    fn rustls_cert_variants_map_to_tls_subclasses() {
        let cases = [
            (
                RustlsError::InvalidCertificate(CertificateError::NotValidForName),
                "cert.name_invalid",
            ),
            (
                RustlsError::InvalidCertificate(CertificateError::Expired),
                "cert.date_invalid",
            ),
            (
                RustlsError::InvalidCertificate(CertificateError::NotValidYet),
                "cert.date_invalid",
            ),
            (
                RustlsError::InvalidCertificate(CertificateError::UnknownIssuer),
                "cert.authority_invalid",
            ),
            (
                RustlsError::InvalidCertificate(CertificateError::Revoked),
                "cert.revoked",
            ),
            (
                RustlsError::InvalidCertificate(CertificateError::UnknownRevocationStatus),
                "cert.revoked",
            ),
            (
                RustlsError::InvalidCertificate(CertificateError::ExpiredRevocationList),
                "cert.revoked",
            ),
            (
                RustlsError::InvalidCertificate(CertificateError::BadSignature),
                "cert.invalid",
            ),
            (
                RustlsError::InvalidCertificate(CertificateError::BadEncoding),
                "cert.invalid",
            ),
            (
                RustlsError::InvalidCertificate(CertificateError::InvalidPurpose),
                "cert.invalid",
            ),
        ];

        for (rustls_err, expected_subclass) in cases {
            let nel = rustls_error_to_nel(&rustls_err);
            assert_eq!(nel.class, "tls");
            assert_eq!(
                nel.subclass, expected_subclass,
                "{rustls_err:?} should map to tls.{expected_subclass}",
            );
            assert_eq!(nel.phase(), "connection");
        }
    }

    #[test]
    fn non_certificate_rustls_errors_fall_through_to_protocol_error() {
        let nel = rustls_error_to_nel(&RustlsError::NoApplicationProtocol);
        assert_eq!(nel.class, "tls");
        assert_eq!(nel.subclass, "protocol.error");
    }

    #[test]
    fn deprecated_unsupported_signature_algorithm_classifies_without_drift_log() {
        // rustls 0.23's webpki verifier still emits the deprecated bare
        // variant. Our match names it explicitly so it doesn't trip the
        // `other` drift-log arm.
        #[allow(deprecated)]
        let err = RustlsError::InvalidCertificate(CertificateError::UnsupportedSignatureAlgorithm);
        let nel = rustls_error_to_nel(&err);
        assert_eq!(nel.class, "tls");
        assert_eq!(nel.subclass, "cert.invalid");
    }

    #[test]
    fn top_level_crl_error_classifies_as_cert_revoked() {
        use rustls::CertRevocationListError;
        let nel = rustls_error_to_nel(&RustlsError::InvalidCertRevocationList(
            CertRevocationListError::BadSignature,
        ));
        assert_eq!(nel.class, "tls");
        assert_eq!(nel.subclass, "cert.revoked");
    }

    #[test]
    fn io_error_with_rustls_source_uses_cert_classification() {
        let wrapped = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            RustlsError::InvalidCertificate(CertificateError::UnknownIssuer),
        );
        let nel: Error = (&wrapped).into();
        assert_eq!(nel.to_string(), "tls.cert.authority_invalid");
    }

    #[test]
    fn nested_io_error_with_rustls_source_uses_cert_classification() {
        // Defensive: handle arbitrary io::Error nesting depth. The reqwest /
        // hyper-util connector stack may layer io::Errors around a rustls
        // error; `find_source<rustls::Error>` should unwrap through them.
        let rustls_err = RustlsError::InvalidCertificate(CertificateError::NotValidForName);
        let inner_io = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_err);
        let outer_io = std::io::Error::new(std::io::ErrorKind::InvalidData, inner_io);

        let nel: Error = (&outer_io).into();
        assert_eq!(nel.to_string(), "tls.cert.name_invalid");
    }

    // -----------------------------------------------------------------
    // Offline substring-branch tests. Each case exercises one fallback
    // wording that would otherwise only be exercised against a live TLS
    // stack. Synthesizing the io::Error text lets the classifier's
    // fragile-by-design text matching rot detectably under CI.
    // -----------------------------------------------------------------

    #[test]
    fn dns_wordings_classify_as_dns_name_not_resolved() {
        let cases = [
            // glibc / musl (Linux CI runner)
            "failed to lookup address information: Name or service not known",
            // libc on macOS / BSD
            "nodename nor servname provided, or not known",
            // Windows
            "No such host is known. (os error 11001)",
            // reqwest's generic wording
            "no address resolved for hostname",
        ];
        for msg in cases {
            let nel = classify_io_error_text(msg).unwrap_or_else(|| {
                panic!("{msg:?} should classify as dns.name_not_resolved but didn't match")
            });
            assert_eq!(nel.to_string(), "dns.name_not_resolved", "for {msg:?}");
        }
    }

    #[test]
    fn unreachable_wordings_classify_as_tcp_address_unreachable() {
        let cases = [
            "No route to host (os error 65)",
            "Network is unreachable (os error 101)",
            "Host is unreachable",
        ];
        for msg in cases {
            let nel = classify_io_error_text(msg)
                .unwrap_or_else(|| panic!("{msg:?} should classify as tcp.address_unreachable"));
            assert_eq!(nel.to_string(), "tcp.address_unreachable", "for {msg:?}");
        }
    }

    #[test]
    fn cert_expiry_wordings_classify_as_tls_cert_date_invalid() {
        // These are the native-tls / OpenSSL / SecureTransport wordings; rustls
        // structured matching catches rustls's own Expired / NotValidYet
        // variants before this fallback fires.
        let cases = [
            "certificate has expired",
            "SEC_E_CERT_EXPIRED: certificate is expired",
            "x509: certificate has an expired certificate",
        ];
        for msg in cases {
            let nel = classify_io_error_text(msg)
                .unwrap_or_else(|| panic!("{msg:?} should classify as tls.cert.date_invalid"));
            assert_eq!(nel.to_string(), "tls.cert.date_invalid", "for {msg:?}");
        }
    }

    #[test]
    fn broad_expired_wording_no_longer_misclassifies_as_tls() {
        // Regression: the earlier `contains("expired")` substring was too
        // broad and grabbed these non-TLS wordings. Confirm they don't now.
        let non_tls_cases = [
            "DHCP lease expired",
            "session expired",
            "authentication cookie expired",
        ];
        for msg in non_tls_cases {
            assert!(
                classify_io_error_text(msg).is_none(),
                "{msg:?} should not match any text classifier"
            );
        }
    }

    #[test]
    fn unrelated_wording_does_not_classify() {
        let cases = [
            "connection reset by peer",
            "broken pipe",
            "operation would block",
            "invalid argument",
        ];
        for msg in cases {
            assert!(
                classify_io_error_text(msg).is_none(),
                "{msg:?} should not match any text classifier"
            );
        }
    }
}
