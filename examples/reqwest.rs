//! End-to-end example using `reqwest` as the HTTP client.
//!
//! Demonstrates:
//! - Spawning `handle_reports` in the background to drain the report queue.
//! - Capturing NEL and Report-To headers from successful responses.
//! - Converting `reqwest::Error` into a classified `nel::Error` via the
//!   provided `From<&reqwest::Error>` impl (enabled by the `reqwest-error`
//!   feature, on by default).

use std::sync::LazyLock;

const ENDPOINT: &str = "https://ivan.computer/";

static NEL_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .user_agent("example-reqwest-nel-rs")
        .build()
        .expect("reqwest client builds")
});

#[tokio::main(flavor = "current_thread")]
pub async fn main() {
    // Spawn a background future to drive reporting.
    tokio::spawn(nel::handle_reports(tokio::time::sleep, post_report));

    let client = reqwest::Client::new();

    // First request: pick up NEL / Report-To policy from the response headers.
    let _ = request(&client, ENDPOINT).await;

    // Second request: a path likely to produce an error so there's something
    // to report.
    let mut query_url = ENDPOINT.to_owned();
    query_url.push_str("dns-query");
    let _ = request(&client, &query_url).await;

    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
}

async fn request(client: &reqwest::Client, url: &str) {
    let resp = client.get(url).send().await;

    match resp {
        Ok(resp) => {
            // Extract the URL host for policy keying; skip header processing
            // if the URL has no host (shouldn't happen for a successful HTTP
            // response, but defensive).
            let Some(host) = resp.url().host_str().map(str::to_owned) else {
                return;
            };

            for (name, value) in resp.headers() {
                let Ok(value) = value.to_str() else { continue };
                if name == "nel" {
                    nel::nel_header(&host, value);
                } else if name == "report-to" {
                    nel::report_to_header(&host, value);
                }
            }

            if !resp.status().is_success() {
                // Cloudflare generally ignores "http.error", so we use
                // "http.response.invalid".
                let error = nel::Error {
                    class: "http".to_owned(),
                    subclass: "response.invalid".to_owned(),
                };
                let mut report = nel::NELReport::new(resp.url().to_string());
                report.set_error(error);
                report.set_status_code(resp.status().as_u16() as usize);
                report.set_method(Some(reqwest::Method::GET));
                nel::submit_report(report);
            }
        }
        Err(err) => {
            let url = err.url().map(ToString::to_string).unwrap_or_default();
            let mut report = nel::NELReport::new(url);
            report.set_error(&err);
            report.set_status_code(0);
            report.set_method(Some(reqwest::Method::GET));
            nel::submit_report(report);
        }
    }
}

async fn post_report(uri: String, payload: String) -> bool {
    let resp = NEL_CLIENT
        .post(uri)
        .header(reqwest::header::CONTENT_TYPE, "application/reports+json")
        .body(payload)
        .send()
        .await;

    eprintln!("nel report resp = {resp:?}");

    // Whether this was successfully reported. Unsuccessful reports are retried
    // indefinitely with a RETRY_TIMEOUT sleep between them.
    resp.map(|r| r.status().is_success()).unwrap_or(false)
}
