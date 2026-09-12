//! Compile a policy against THIS host and print the ruleset, so it can be
//! fed to `nft -c -f -` and judged by the kernel's own parser rather than
//! by whether it looks right.
//!
//!     cargo run -p tl-policy --example emit -- <unit.service>
use std::path::Path as FsPath;
use tl_policy::{Path, Policy, Rule, Selector, probe};

fn main() {
    let host = probe::host(
        FsPath::new("/proc"),
        FsPath::new("/sys"),
        FsPath::new("/etc/tor/torrc"),
    );
    let unit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "cron.service".to_owned());
    let policy = Policy {
        rules: vec![Rule {
            selector: Selector::Unit(unit),
            path: Path::Tor,
        }],
        default_path: Path::Direct,
    };
    let plan = policy.compile(&host);
    for r in plan.preflight(&policy, &host) {
        eprintln!("REFUSED: {}", r.explain());
    }
    eprintln!(
        "-- probed: {} interfaces, {} cgroups, tor uid {:?}, TransPort {:?}, admin peers {:?}",
        host.interfaces.len(),
        host.cgroups.len(),
        host.tor_uid,
        host.tor_trans_port,
        host.admin_peers
    );
    print!("{}", plan.nft);
}
