//! Compile a routing policy from the command line.
//!
//! The editor in the browser and this binary compile through exactly the
//! same code, so what the screen shows and what a script produces cannot
//! drift apart. It also makes the compiler testable against a host that
//! is not this one: every probed fact can be overridden, which is how the
//! namespace test suite compiles policies for a machine that exists for
//! four seconds.
//!
//!     tl-plan --default direct --rule cgroup:system.slice/nginx.service=vpn:wg0 \
//!             --admin 203.0.113.7
//!
//! Prints the ruleset on stdout and everything else on stderr, so
//! `tl-plan ... | nft -f -` is the obvious thing and also the correct one.
//! Exits non-zero if the plan must not be applied.

use std::path::Path as FsPath;
use std::process::ExitCode;

use tl_policy::{Host, Path, Policy, Rule, Selector, probe};

const USAGE: &str = "\
tl-plan — compile a per-application routing policy

  --default <path>            where everything not named goes (default: direct)
  --rule <selector>=<path>    one program's route; repeatable
  --admin <addr>              a session that must keep working; repeatable
  --endpoint <addr>           an address that must stay outside any tunnel

  <selector>  unit:<name> | cgroup:<path> | uid:<n>
  <path>      direct | tor | vpn:<iface> | tor-via:<iface>

Overrides, for compiling against a host that is not this one:
  --iface <name>              add an interface; repeatable
  --cgroup <path>             add a known cgroup; repeatable
  --tor-trans <port>          Tor's TransPort
  --tor-dns <port>            Tor's DNSPort
  --tor-uid <uid>             the uid Tor runs as
  --rp-filter <iface>=<0|1|2> reverse-path filter setting; repeatable
  --bare                      start from nothing instead of probing this host

  --ip                        also print the ip commands, commented
  --force                     print the ruleset even if it must not be applied

Changing the machine (needs root):
  --apply                     put the plan into the kernel
  --deadman <secs>            undo it automatically unless confirmed (default 120)
  --verify <host:port>        after applying, open a NEW connection there; if it
                              fails, undo immediately. An EXISTING session
                              surviving proves nothing -- every open flow is
                              excluded by construction.
  --confirm                   keep what is applied; cancel the countdown
  --revert                    undo whatever is applied
  --status                    say what is actually in the kernel right now
  --dry-run                   print the commands instead of running them
  --netns <name>              do all of it inside a network namespace
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let bare = args.iter().any(|a| a == "--bare");
    let mut host = if bare {
        Host::default()
    } else {
        probe::host(
            FsPath::new("/proc"),
            FsPath::new("/sys"),
            FsPath::new("/etc/tor/torrc"),
        )
    };
    // Probing cannot know which inbound session is the operator's, so it
    // never guesses; `--admin` is how a caller says.
    host.admin_peers.clear();

    let mut policy = Policy::default();
    let mut show_ip = false;
    let mut force = false;
    let mut opts = tl_policy::apply::Options::default();
    let mut verb = "";
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let mut val = || -> Option<String> {
            i += 1;
            args.get(i).cloned()
        };
        let bad = |what: &str, v: &str| -> ExitCode {
            eprintln!("tl-plan: {what}: {v:?}\n\n{USAGE}");
            ExitCode::FAILURE
        };
        match arg {
            "--bare" => {}
            "--ip" => show_ip = true,
            "--force" => force = true,
            "--apply" | "--revert" | "--confirm" | "--status" => verb = arg,
            "--dry-run" => opts.dry_run = true,
            "--deadman" => match val().and_then(|v| v.parse().ok()) {
                Some(n) => opts.deadman_secs = n,
                None => return bad("not a number of seconds", arg),
            },
            "--verify" => match val() {
                Some(v) => opts.verify = Some(v),
                None => return bad("missing value", arg),
            },
            "--netns" => match val() {
                Some(v) => opts.netns = Some(v),
                None => return bad("missing value", arg),
            },
            "--default" => match val().as_deref().and_then(parse_path) {
                Some(p) => policy.default_path = p,
                None => return bad("not a path", arg),
            },
            "--rule" => {
                let Some(v) = val() else {
                    return bad("missing value", arg);
                };
                let Some((sel, path)) = v.rsplit_once('=') else {
                    return bad("not <selector>=<path>", &v);
                };
                match (parse_selector(sel), parse_path(path)) {
                    (Some(s), Some(p)) => policy.rules.push(Rule {
                        selector: s,
                        path: p,
                    }),
                    _ => return bad("not <selector>=<path>", &v),
                }
            }
            "--admin" => match val() {
                Some(v) => host.admin_peers.push(v),
                None => return bad("missing value", arg),
            },
            "--endpoint" => match val() {
                Some(v) => host.tunnel_endpoints.push(v),
                None => return bad("missing value", arg),
            },
            "--iface" => match val() {
                Some(v) => host.interfaces.push(v),
                None => return bad("missing value", arg),
            },
            "--cgroup" => match val() {
                Some(v) => host.cgroups.push(v),
                None => return bad("missing value", arg),
            },
            "--tor-trans" => host.tor_trans_port = val().and_then(|v| v.parse().ok()),
            "--tor-dns" => host.tor_dns_port = val().and_then(|v| v.parse().ok()),
            "--tor-uid" => host.tor_uid = val().and_then(|v| v.parse().ok()),
            "--rp-filter" => {
                let Some(v) = val() else {
                    return bad("missing value", arg);
                };
                match v
                    .split_once('=')
                    .and_then(|(n, s)| Some((n.to_owned(), s.parse().ok()?)))
                {
                    Some(pair) => host.rp_filter.push(pair),
                    None => return bad("not <iface>=<0|1|2>", &v),
                }
            }
            other => return bad("unknown argument", other),
        }
        i += 1;
    }

    // Verbs that read or undo do not need a policy at all.
    match verb {
        "--status" => {
            let st = tl_policy::apply::status(&opts);
            println!("{}", st.describe());
            println!(
                "  record={} table={} routing={} countdown={}",
                st.recorded, st.table_present, st.rules_present, st.deadman_armed
            );
            if tl_policy::apply::baseline_flushes(std::path::Path::new("/etc/nftables.conf")) {
                println!(
                    "  note: /etc/nftables.conf flushes the ruleset, so reloading the \
                     baseline firewall will silently remove this policy while leaving \
                     the routing half in place."
                );
            }
            return ExitCode::SUCCESS;
        }
        "--revert" => {
            return match tl_policy::apply::revert(&opts) {
                Ok(a) => {
                    for c in &a.revert {
                        eprintln!("undone: {c}");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("tl-plan: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        "--confirm" => {
            return match tl_policy::apply::confirm(&opts) {
                Ok(_) => {
                    eprintln!("kept. The countdown is cancelled.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("tl-plan: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        _ => {}
    }

    let plan = policy.compile(&host);
    let refusals = plan.preflight(&policy, &host);
    for r in &refusals {
        eprintln!("REFUSED: {}", r.explain());
    }
    for n in &plan.notes {
        eprintln!("note: {n}");
    }
    if !refusals.is_empty() && !force {
        eprintln!(
            "\ntl-plan: refusing to print a ruleset that must not be applied. \
             Fix the above, or pass --force to see it anyway."
        );
        return ExitCode::FAILURE;
    }

    if verb == "--apply" {
        return match tl_policy::apply::apply(&policy, &host, &plan, &opts) {
            Ok(a) if opts.dry_run => {
                let _ = a;
                ExitCode::SUCCESS
            }
            Ok(a) => {
                if a.deadman {
                    eprintln!(
                        "applied. It will undo itself in {}s unless you run --confirm.\n\
                         Before you do: open a NEW connection and check it works. An \
                         existing session still working proves nothing -- every flow \
                         that was already open is excluded by construction.",
                        opts.deadman_secs
                    );
                } else {
                    eprintln!("applied, with NO countdown. Nothing will undo this for you.");
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("tl-plan: {e}");
                ExitCode::FAILURE
            }
        };
    }

    print!("{}", plan.nft);
    if show_ip {
        for c in &plan.ip {
            println!("# {c}");
        }
    } else {
        for c in &plan.ip {
            eprintln!("{c}");
        }
    }
    for c in &plan.torrc {
        eprintln!("torrc: {c}");
    }
    ExitCode::SUCCESS
}

fn parse_path(s: &str) -> Option<Path> {
    match s.split_once(':') {
        Some(("vpn", i)) if !i.is_empty() => Some(Path::Vpn {
            interface: i.to_owned(),
        }),
        Some(("tor-via", i)) if !i.is_empty() => Some(Path::TorViaVpn {
            interface: i.to_owned(),
        }),
        Some(_) => None,
        None => match s {
            "direct" => Some(Path::Direct),
            "tor" => Some(Path::Tor),
            _ => None,
        },
    }
}

fn parse_selector(s: &str) -> Option<Selector> {
    match s.split_once(':') {
        Some(("unit", n)) if !n.is_empty() => Some(Selector::Unit(n.to_owned())),
        Some(("cgroup", p)) if !p.is_empty() => Some(Selector::Cgroup(p.to_owned())),
        Some(("uid", n)) => n.parse().ok().map(Selector::User),
        _ => None,
    }
}
