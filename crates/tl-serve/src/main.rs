//! Local-only HTTP server for the Throughline view.
//!
//! Binds loopback and nothing else, by construction rather than by
//! configuration. A tool whose screen enumerates every process on the
//! machine and everything it talks to is a reconnaissance report; it does
//! not get a listening port on a network interface, and there is no flag
//! to make it one.
//!
//! Binding loopback is necessary and not sufficient. Two things reach a
//! loopback port anyway, and both are handled here rather than assumed
//! away:
//!
//! * **A browser can be made to resolve an attacker's domain to
//!   127.0.0.1.** The page is then same-origin with this server and can
//!   read `/api/snapshot` — the whole inventory — and send it anywhere.
//!   Binding loopback does not stop it; checking the `Host` header does.
//! * **Any local user can open a connection and never finish it.** The
//!   accept loop is serial, so one silent client denies the tool to
//!   everybody. Timeouts and size caps bound that.
//!
//! std only — no framework. The surface is two GET routes, and a
//! dependency tree is a thing a reader of this program would have to audit
//! before believing the rest of it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

mod api;
mod gate;

use tl_inventory::ports::EphemeralPorts;
use tl_inventory::services::ServiceNames;
use tl_inventory::snapshot;

const INDEX: &str = include_str!("../assets/index.html");

/// Longest request line or header we will read. Generous for a URL,
/// small enough that a client cannot make us allocate.
const MAX_LINE: u64 = 8 * 1024;
/// Enough for any real browser; a client sending more is not one.
const MAX_HEADERS: usize = 64;
/// A request that goes quiet for this long is abandoned, so the serial
/// accept loop keeps moving.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(7644);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("throughline: cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    let gate = gate::Gate::new();
    println!("throughline: http://{addr}  (loopback only)");
    if gate.token().is_empty() {
        println!(
            "  could not read /dev/urandom, so routing cannot be changed from the \
             browser. Use tl-plan directly."
        );
    } else {
        // Printed here and nowhere else. This is the whole point: a page
        // that merely reached this server cannot know it, and a person at
        // the terminal can read it off.
        println!("  to change routing from the browser, paste this once: {}", gate.token());
    }
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                // Serial on purpose. One viewer, and a scan that overlaps
                // itself would show two half-snapshots interleaved. The
                // timeouts above are what make serial safe.
                if let Err(e) = handle(s, &gate) {
                    eprintln!("throughline: {e}");
                }
            }
            Err(e) => eprintln!("throughline: accept: {e}"),
        }
    }
}

/// Whether a `Host` header names this machine.
///
/// This is the whole defence against DNS rebinding. An attacker who
/// controls `evil.example` can point it at 127.0.0.1; the browser then
/// treats their page and this server as one origin and hands them the
/// inventory. The request still carries `Host: evil.example`, and that is
/// the part they cannot forge away — a browser always sends the name it
/// was asked for.
///
/// An absent `Host` is allowed: HTTP/1.0 clients and `curl --http1.0`
/// omit it, and the attack requires a browser, which never does.
#[must_use]
fn host_is_local(host: &str) -> bool {
    let host = host.trim();
    if host.is_empty() {
        return true;
    }
    // Strip the port. An IPv6 literal is bracketed, so a colon inside
    // brackets is part of the address and must not be cut there.
    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            // Only ":port" may follow the bracket. Accepting anything
            // there read "[::1].evil.example" as the loopback address it
            // merely starts with, which is the whole attack.
            Some((inner, after))
                if after.is_empty()
                    || after
                        .strip_prefix(':')
                        .is_some_and(|p| p.parse::<u16>().is_ok()) =>
            {
                inner
            }
            _ => return false,
        }
    } else {
        let mut parts = host.split(':');
        let name = parts.next().unwrap_or(host);
        // Likewise for the unbracketed form: at most one colon, and what
        // follows it must be a port.
        match parts.next() {
            Some(port) if parts.next().is_some() || port.parse::<u16>().is_err() => {
                return false;
            }
            _ => name,
        }
    };
    if name.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // Any address that parses must be a loopback one. Note 127.0.0.0/8 is
    // loopback in full, not just 127.0.0.1.
    name.parse::<IpAddr>().is_ok_and(|a| a.is_loopback())
}

/// Overridable so the tool works against a container's bound `/proc` or
/// a captured tree.
fn proc_root() -> String {
    std::env::var("TL_PROC").unwrap_or_else(|_| "/proc".to_owned())
}

fn torrc() -> String {
    std::env::var("TL_TORRC").unwrap_or_else(|_| "/etc/tor/torrc".to_owned())
}

fn handle(mut stream: TcpStream, gate: &gate::Gate) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut line = String::new();
    read_capped(&mut reader, &mut line)?;
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();

    // Read headers rather than merely draining them: the Host matters, and
    // a client that never sends the blank line must not be able to hold
    // the loop open until its timeout, over and over.
    let mut host = String::new();
    let mut h = String::new();
    for _ in 0..MAX_HEADERS {
        if read_capped(&mut reader, &mut h)? <= 2 {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                host = v.trim().to_owned();
            }
        }
    }

    if !host_is_local(&host) {
        // Deliberately terse: an attacker's page learns only that it was
        // refused, and a real user sees the reason in the tool's log.
        eprintln!("throughline: refused request for Host: {host}");
        return respond(
            &mut stream,
            "421 Misdirected Request",
            "text/plain; charset=utf-8",
            "this server answers only to localhost",
        );
    }

    let (status, ctype, body) = match path.split('?').next().unwrap_or("/") {
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", INDEX.to_owned()),
        "/api/snapshot" => {
            // Both paths are overridable so the tool works somewhere other
            // than a conventional host — a container with /proc bound
            // elsewhere, or a captured tree being examined after the fact.
            let proc_root = proc_root();
            let services =
                std::env::var("TL_SERVICES").unwrap_or_else(|_| "/etc/services".to_owned());
            let flows = snapshot::collect(Path::new(&proc_root));
            let names = ServiceNames::load(Path::new(&services));
            let ports = EphemeralPorts::load(Path::new(&proc_root));
            (
                "200 OK",
                "application/json; charset=utf-8",
                snapshot::to_json(&flows, &names, ports),
            )
        }
        "/api/host" => {
            let host = tl_policy::probe::host(
                std::path::Path::new(&proc_root()),
                std::path::Path::new("/sys"),
                std::path::Path::new(&torrc()),
            );
            let sessions = tl_policy::probe::admin_candidates(std::path::Path::new(&proc_root()));
            let active = tl_policy::probe::active_cgroups(std::path::Path::new(&proc_root()));
            (
                "200 OK",
                "application/json; charset=utf-8",
                api::host_json(&host, &sessions, &active),
            )
        }
        "/api/plan" => {
            let query = path.split_once('?').map_or("", |(_, q)| q);
            let base = tl_policy::probe::host(
                std::path::Path::new(&proc_root()),
                std::path::Path::new("/sys"),
                std::path::Path::new(&torrc()),
            );
            let (policy, host, bad) = api::policy_from_query(query, base);
            (
                "200 OK",
                "application/json; charset=utf-8",
                api::plan_json(&policy, &host, &bad, &api::apply_command(query)),
            )
        }
        // ---- the three that change the machine ------------------------
        p @ ("/api/apply" | "/api/confirm" | "/api/revert") => {
            let query = path.split_once('?').map_or("", |(_, q)| q);
            let token = api::params(query)
                .into_iter()
                .find(|(k, _)| k == "token")
                .map(|(_, v)| v);
            if !gate.allows(token.as_deref()) {
                eprintln!("throughline: refused {p} — wrong or missing token");
                return respond(
                    &mut stream,
                    "403 Forbidden",
                    "application/json; charset=utf-8",
                    concat!(
                        r#"{"error":"Paste the token printed by tl-serve on the "#,
                        r#"terminal it was started from. A page that can merely reach "#,
                        r#"this server does not have it."}"#
                    ),
                );
            }
            let out = api::do_write(p, query);
            (
                if out.starts_with("{\"error\"") { "400 Bad Request" } else { "200 OK" },
                "application/json; charset=utf-8",
                out,
            )
        }
        "/api/status" => {
            let st = tl_policy::apply::status(&tl_policy::apply::Options {
                netns: std::env::var("TL_NETNS").ok().filter(|v| !v.is_empty()),
                ..tl_policy::apply::Options::default()
            });
            (
                "200 OK",
                "application/json; charset=utf-8",
                format!(
                    "{{\"text\":\"{}\",\"recorded\":{},\"table\":{},\"routing\":{},\
                     \"countdown\":{},\"baselineFlushes\":{}}}",
                    api::esc(&st.describe()),
                    st.recorded,
                    st.table_present,
                    st.rules_present,
                    st.deadman_armed,
                    tl_policy::apply::baseline_flushes(Path::new("/etc/nftables.conf")),
                ),
            )
        }
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found".to_owned(),
        ),
    };
    respond(&mut stream, status, ctype, &body)
}

/// Read one line, refusing to grow without bound.
///
/// `BufRead::read_line` has no limit: a client that sends megabytes with
/// no newline makes the server allocate all of it. Capping the read means
/// an over-long line is truncated and then fails to parse, which is the
/// correct outcome.
fn read_capped(reader: &mut impl BufRead, buf: &mut String) -> std::io::Result<usize> {
    buf.clear();
    reader.by_ref().take(MAX_LINE).read_line(buf)
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    ctype: &str,
    body: &str,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_by_any_of_its_own_names_is_accepted() {
        for h in [
            "",
            "localhost",
            "LocalHost:7644",
            "127.0.0.1",
            "127.0.0.1:7644",
            "127.1.2.3",   // 127.0.0.0/8 is loopback in full
            "[::1]",
            "[::1]:7644",
        ] {
            assert!(host_is_local(h), "should accept {h:?}");
        }
    }

    #[test]
    fn a_rebound_domain_is_refused_even_though_it_resolved_here() {
        // This is the attack: the name resolves to 127.0.0.1, so the
        // connection genuinely arrives on loopback and the browser calls
        // it same-origin. The Host header is what gives it away.
        for h in [
            "evil.example",
            "evil.example:7644",
            "127.0.0.1.evil.example",     // prefix that looks loopback
            "localhost.evil.example",
            "[::1].evil.example",         // starts loopback, is not
            "[::1]evil.example",
            "[::1]:7644.evil",
            "localhost:not-a-port",
            "127.0.0.1:1:2",
            "0.0.0.0",                    // routable to us, not a local name
            "192.168.1.10:7644",
            "[fe80::1]",
        ] {
            assert!(!host_is_local(h), "should refuse {h:?}");
        }
    }

    #[test]
    fn a_malformed_host_is_refused_rather_than_guessed_at() {
        for h in ["[::1", "[", "[]", "not a host"] {
            assert!(!host_is_local(h), "should refuse {h:?}");
        }
    }

    #[test]
    fn an_over_long_line_is_truncated_instead_of_allocated() {
        // A client sending megabytes with no newline must not make the
        // server grow to match.
        let huge = vec![b'a'; (MAX_LINE as usize) * 4];
        let mut r = BufReader::new(&huge[..]);
        let mut buf = String::new();
        let n = read_capped(&mut r, &mut buf).unwrap();
        assert_eq!(n, MAX_LINE as usize);
        assert_eq!(buf.len(), MAX_LINE as usize);
    }
}
