//! Local-only HTTP server for the Throughline view.
//!
//! Binds loopback and nothing else, by construction rather than by
//! configuration. A tool whose screen enumerates every process on the
//! machine and everything it talks to is a reconnaissance report; it does
//! not get a listening port on a network interface, and there is no flag
//! to make it one.
//!
//! std only — no framework. The surface is two GET routes, and a
//! dependency tree is a thing a reader of this program would have to audit
//! before believing the rest of it.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;

use tl_inventory::snapshot;

const INDEX: &str = include_str!("../assets/index.html");

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
    println!("throughline: http://{addr}  (loopback only)");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                // Serial on purpose. One viewer, and a scan that overlaps
                // itself would show two half-snapshots interleaved.
                if let Err(e) = handle(s) {
                    eprintln!("throughline: {e}");
                }
            }
            Err(e) => eprintln!("throughline: accept: {e}"),
        }
    }
}

fn handle(mut stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
    // Drain headers so the client sees a clean response rather than a reset.
    let mut h = String::new();
    while reader.read_line(&mut h)? > 2 {
        h.clear();
    }

    let (status, ctype, body) = match path.split('?').next().unwrap_or("/") {
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", INDEX.to_owned()),
        "/api/snapshot" => {
            let flows = snapshot::collect(Path::new("/proc"));
            (
                "200 OK",
                "application/json; charset=utf-8",
                snapshot::to_json(&flows),
            )
        }
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found".to_owned()),
    };

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
