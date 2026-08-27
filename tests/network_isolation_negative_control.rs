//! Negative control for the offline-generation CI proof (P3-02).
//!
//! This test deliberately makes a real outbound network connection. It is
//! **expected to fail** under the `offline-generation` CI job's
//! network-isolated step — that failure is the proof the isolation is real.
//!
//! An in-process "am I offline?" assertion can only observe the paths it
//! knows to instrument, so it would pass even if some dependency three
//! levels down still had a route out. Denying the capability at the
//! boundary (see `.github/workflows/ci.yml`, job `offline-generation`,
//! which runs this inside a network namespace with no interface) is the
//! only proof that actually holds. If this test ever *passes* while running
//! inside that isolated step, the isolation has silently broken and the
//! "generation works offline" claim in the README is unproven — the CI
//! step inverts this test's result specifically to catch that.

use std::net::TcpStream;
use std::time::Duration;

/// Attempts a real outbound TCP connection to a public host, by IP literal
/// (no DNS dependency). Expected to succeed whenever a network route exists,
/// and to fail (`Network is unreachable` / timeout) when run inside a
/// network namespace with no interface, such as CI's isolated step.
#[test]
fn network_call_succeeds_when_a_route_exists() {
    let addr = "1.1.1.1:443"
        .parse()
        .expect("literal socket address must parse");

    let result = TcpStream::connect_timeout(&addr, Duration::from_secs(5));

    assert!(
        result.is_ok(),
        "expected outbound TCP connect to {addr} to succeed (no network isolation active); \
         got error: {:?}. If this failure happened inside the offline-generation CI job's \
         isolated step, that is the *expected*, desired outcome — see ci.yml.",
        result.err()
    );
}
