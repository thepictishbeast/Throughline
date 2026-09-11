//! The two routing endpoints, and the query format they speak.
//!
//! A policy arrives as query parameters rather than a JSON body. This
//! crate has no dependencies, and a hand-written JSON *parser* is a
//! different proposition from a hand-written serialiser: the serialiser
//! only has to render values this program produced, while a parser has to
//! survive whatever arrives. Query parsing is small enough to read in one
//! sitting and test exhaustively.
//!
//!     /api/plan?admin=203.0.113.7
//!              &default=tor
//!              &rule=unit:nginx.service=direct
//!              &rule=uid:1000=vpn:wg0
//!
//! Nothing here applies anything. Both endpoints are reads that happen to
//! take arguments.

use tl_policy::{Host, Path, Policy, Rule, Selector};

/// Split a query string into key/value pairs, percent-decoded.
#[must_use]
pub fn params(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

/// Percent-decoding, plus `+` for space.
///
/// Invalid escapes are left as written rather than dropped. A selector is
/// matched against a kernel path, so silently altering it would produce a
/// rule that matches nothing — and a rule that matches nothing looks
/// exactly like a policy that applied.
#[must_use]
pub fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v as char);
                    i += 3;
                } else {
                    out.push('%');
                    i += 1;
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// `direct` | `tor` | `vpn:<iface>` | `tor-via:<iface>`
#[must_use]
pub fn parse_path(s: &str) -> Option<Path> {
    match s.split_once(':') {
        Some(("vpn", i)) if !i.is_empty() => Some(Path::Vpn { interface: i.to_owned() }),
        Some(("tor-via", i)) if !i.is_empty() => {
            Some(Path::TorViaVpn { interface: i.to_owned() })
        }
        Some(_) => None,
        None => match s {
            "direct" => Some(Path::Direct),
            "tor" => Some(Path::Tor),
            _ => None,
        },
    }
}

/// `unit:<name>` | `cgroup:<path>` | `uid:<n>`
#[must_use]
pub fn parse_selector(s: &str) -> Option<Selector> {
    match s.split_once(':') {
        Some(("unit", n)) if !n.is_empty() => Some(Selector::Unit(n.to_owned())),
        Some(("cgroup", p)) if !p.is_empty() => Some(Selector::Cgroup(p.to_owned())),
        Some(("uid", n)) => n.parse().ok().map(Selector::User),
        _ => None,
    }
}

/// Build a policy and the host it is compiled against.
///
/// `admin` values come from the request because the operator confirms
/// them; see [`tl_policy::probe::admin_candidates`] for why they are not
/// simply detected. An unparseable parameter is reported rather than
/// skipped — a dropped rule is a policy that quietly does less than it
/// says.
#[must_use]
pub fn policy_from_query(query: &str, base: Host) -> (Policy, Host, Vec<String>) {
    let mut policy = Policy::default();
    let mut host = base;
    host.admin_peers.clear();
    let mut bad = Vec::new();

    for (k, v) in params(query) {
        match k.as_str() {
            "default" => match parse_path(&v) {
                Some(p) => policy.default_path = p,
                None => bad.push(format!("unknown path {v:?}")),
            },
            "rule" => {
                let Some((sel, path)) = v.rsplit_once('=') else {
                    bad.push(format!("rule {v:?} is not <selector>=<path>"));
                    continue;
                };
                match (parse_selector(sel), parse_path(path)) {
                    (Some(s), Some(p)) => policy.rules.push(Rule { selector: s, path: p }),
                    (None, _) => bad.push(format!("unknown selector {sel:?}")),
                    (_, None) => bad.push(format!("unknown path {path:?}")),
                }
            }
            "admin" if !v.is_empty() => host.admin_peers.push(v),
            "endpoint" if !v.is_empty() => host.tunnel_endpoints.push(v),
            _ => {}
        }
    }
    (policy, host, bad)
}

/// JSON string escaping, matching the inventory crate's.
#[must_use]
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                o.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => o.push(c),
        }
    }
    o
}

fn arr(items: impl Iterator<Item = String>) -> String {
    let v: Vec<String> = items.map(|s| format!("\"{}\"", esc(&s))).collect();
    format!("[{}]", v.join(","))
}

/// What the host offers: interfaces, selectable cgroups, Tor's state, and
/// the sessions a person needs to confirm.
#[must_use]
pub fn host_json(
    host: &Host,
    sessions: &[tl_policy::probe::AdminSession],
    active: &[String],
) -> String {
    let s: Vec<String> = sessions
        .iter()
        .map(|c| {
            format!(
                "{{\"peer\":\"{}\",\"port\":{},\"holder\":\"{}\",\"likely\":{},\"evidence\":\"{}\"}}",
                esc(&c.peer),
                c.port,
                esc(&c.holder),
                c.likely,
                esc(&c.evidence)
            )
        })
        .collect();
    format!(
        "{{\"interfaces\":{},\"cgroups\":{},\"active\":{},\"torTransPort\":{},\
         \"torDnsPort\":{},\"torUid\":{},\"sessions\":[{}]}}",
        arr(host.interfaces.iter().cloned()),
        arr(host.cgroups.iter().cloned()),
        arr(active.iter().cloned()),
        host.tor_trans_port.map_or("null".to_owned(), |p| p.to_string()),
        host.tor_dns_port.map_or("null".to_owned(), |p| p.to_string()),
        host.tor_uid.map_or("null".to_owned(), |u| u.to_string()),
        s.join(",")
    )
}

/// The command that would apply this plan, exactly as it must be typed.
///
/// The browser does not apply anything. This server runs as root so that
/// it can read every process's sockets, and a routing change reachable
/// from a web request is a different thing entirely — a page in a browser
/// that was told an attacker's name resolves to 127.0.0.1 is same-origin
/// with it. Reading is worth that risk with a Host check in front of it;
/// rewriting the machine's routing is not.
///
/// So the screen produces the command and a person runs it. Nothing is
/// lost: it is the same compiler, and `--status` reads back into the same
/// page.
#[must_use]
pub fn apply_command(query: &str) -> String {
    let mut cmd = vec!["sudo tl-plan".to_owned()];
    let mut rules = Vec::new();
    for (k, v) in params(query) {
        match k.as_str() {
            "default" => cmd.push(format!("--default {v}")),
            "rule" => rules.push(format!("--rule '{v}'")),
            "admin" if !v.is_empty() => cmd.push(format!("--admin {v}")),
            "endpoint" if !v.is_empty() => cmd.push(format!("--endpoint {v}")),
            _ => {}
        }
    }
    cmd.extend(rules);
    cmd.push("--apply --deadman 120".to_owned());
    cmd.join(" \\\n    ")
}

/// A compiled plan plus everything wrong with it.
#[must_use]
pub fn plan_json(policy: &Policy, host: &Host, bad: &[String], command: &str) -> String {
    let plan = policy.compile(host);
    let refusals: Vec<String> = plan
        .preflight(policy, host)
        .iter()
        .map(tl_policy::Refusal::explain)
        .collect();
    let marks: Vec<String> = plan
        .marks
        .iter()
        .map(|(k, v)| format!("{{\"path\":\"{}\",\"mark\":\"{v:#x}\"}}", esc(k)))
        .collect();
    format!(
        "{{\"nft\":\"{}\",\"ip\":{},\"torrc\":{},\"notes\":{},\"refusals\":{},\
         \"malformed\":{},\"marks\":[{}],\"applyable\":{},\"revert\":{},\"command\":\"{}\"}}",
        esc(&plan.nft),
        arr(plan.ip.iter().cloned()),
        arr(plan.torrc.iter().cloned()),
        arr(plan.notes.iter().cloned()),
        arr(refusals.iter().cloned()),
        arr(bad.iter().cloned()),
        marks.join(","),
        refusals.is_empty() && bad.is_empty(),
        arr(plan.revert.iter().cloned()),
        esc(command),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        Host {
            interfaces: vec!["wg0".into()],
            tor_trans_port: Some(9040),
            tor_dns_port: Some(9053),
            tor_uid: Some(105),
            admin_peers: vec![],
            tunnel_endpoints: vec![],
            rp_filter: vec![("all".into(), 2), ("wg0".into(), 2)],
            cgroups: vec!["system.slice/nginx.service".into()],
        }
    }

    #[test]
    fn the_host_json_survives_a_cgroup_name_with_a_quote_in_it() {
        // Directory names come from the filesystem; a unit could be named
        // anything and one stray quote blanks the whole editor.
        let mut h = host();
        h.cgroups.push("system.slice/ev\"il.service".into());
        let j = host_json(&h, &[], &["system.slice/ev\"il.service".into()]);
        assert!(!j.contains("ev\"il"), "unescaped quote reached the UI: {j}");
        assert!(j.contains("ev\\\"il"), "{j}");
        assert!(j.contains("\"active\""));
    }

    #[test]
    fn a_policy_round_trips_from_a_query_string() {
        let (p, h, bad) = policy_from_query(
            "default=tor&rule=unit:nginx.service=direct&rule=uid:1000=vpn:wg0&admin=203.0.113.7",
            host(),
        );
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(p.default_path, Path::Tor);
        assert_eq!(p.rules.len(), 2);
        assert_eq!(p.rules[0].selector, Selector::Unit("nginx.service".into()));
        assert_eq!(p.rules[0].path, Path::Direct);
        assert_eq!(p.rules[1].selector, Selector::User(1000));
        assert_eq!(p.rules[1].path, Path::Vpn { interface: "wg0".into() });
        assert_eq!(h.admin_peers, vec!["203.0.113.7".to_owned()]);
    }

    #[test]
    fn a_selector_containing_a_path_separator_survives_encoding() {
        // A cgroup selector is full of slashes and the rule format uses
        // `=` as its own separator, so both have to come back intact or
        // the rule silently matches nothing.
        let (p, _, bad) = policy_from_query(
            "rule=cgroup%3Auser.slice%2Fuser-1000.slice%2Fsession-3.scope=tor",
            host(),
        );
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(
            p.rules[0].selector,
            Selector::Cgroup("user.slice/user-1000.slice/session-3.scope".into())
        );
    }

    #[test]
    fn an_unparseable_rule_is_reported_not_dropped() {
        // Skipping it would produce a policy that quietly does less than
        // the screen says it does.
        let (p, _, bad) = policy_from_query(
            "rule=unit:nginx.service=teleport&rule=wat:x=tor&rule=nonsense&default=sideways",
            host(),
        );
        assert!(p.rules.is_empty());
        assert_eq!(p.default_path, Path::Direct, "unchanged when unparseable");
        assert_eq!(bad.len(), 4, "{bad:?}");
        assert!(bad.iter().any(|b| b.contains("teleport")));
        assert!(bad.iter().any(|b| b.contains("not <selector>=<path>")));
    }

    #[test]
    fn every_path_spelling_parses_and_nothing_else_does() {
        assert_eq!(parse_path("direct"), Some(Path::Direct));
        assert_eq!(parse_path("tor"), Some(Path::Tor));
        assert_eq!(parse_path("vpn:wg0"), Some(Path::Vpn { interface: "wg0".into() }));
        assert_eq!(
            parse_path("tor-via:wg0"),
            Some(Path::TorViaVpn { interface: "wg0".into() })
        );
        for bad in ["", "vpn", "vpn:", "tor-via:", "TOR", "tor ", "direct:x"] {
            assert_eq!(parse_path(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_apply_command_carries_every_part_of_the_policy() {
        // If the command the screen shows is not the policy the screen
        // shows, the person running it applies something else.
        let c = apply_command(
            "default=tor&rule=uid%3A1000=vpn%3Awg0&rule=unit%3Anginx.service=direct&admin=203.0.113.7",
        );
        assert!(c.contains("--default tor"), "{c}");
        assert!(c.contains("--rule 'uid:1000=vpn:wg0'"), "{c}");
        assert!(c.contains("--rule 'unit:nginx.service=direct'"), "{c}");
        assert!(c.contains("--admin 203.0.113.7"), "{c}");
        assert!(c.contains("--apply"), "{c}");
        assert!(c.contains("--deadman 120"), "the countdown is not optional: {c}");
    }

    #[test]
    fn a_plan_that_cannot_be_applied_says_so_and_says_why() {
        let (p, h, bad) = policy_from_query("default=tor&admin=203.0.113.7", host());
        let j = plan_json(&p, &h, &bad, "");
        assert!(j.contains("\"applyable\":true"), "{j}");

        // The same policy on a host whose Tor has no transparent port.
        let mut bare = host();
        bare.tor_trans_port = None;
        let (p2, h2, bad2) = policy_from_query("default=tor&admin=203.0.113.7", bare);
        let j2 = plan_json(&p2, &h2, &bad2, "");
        assert!(j2.contains("\"applyable\":false"), "{j2}");
        assert!(j2.contains("TransPort"), "{j2}");
    }

    #[test]
    fn the_generated_json_survives_a_hostile_selector() {
        // A cgroup name comes from the filesystem and a unit name from a
        // request. Either could carry a quote and blank the whole view.
        let (p, h, _) = policy_from_query("rule=unit:evil%22name.service=tor", host());
        let j = plan_json(&p, &h, &[], "");
        assert!(!j.contains("evil\"name"), "unescaped quote reached the UI");
        assert!(j.contains("evil\\\"name") || j.contains("evil%22name"), "{j}");
    }

    #[test]
    fn a_malformed_percent_escape_is_left_alone_rather_than_dropped() {
        assert_eq!(decode("a%zzb"), "a%zzb");
        assert_eq!(decode("a%2"), "a%2");
        assert_eq!(decode("a+b%2Fc"), "a b/c");
    }
}
