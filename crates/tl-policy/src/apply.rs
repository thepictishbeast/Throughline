//! Putting a plan into the kernel, and getting it back out again.
//!
//! Everything else in this crate produces text. This is the only part
//! that changes the machine, and the whole design is about the ways that
//! goes wrong.
//!
//! **Fail closed.** `nft -f` is one atomic kernel transaction — all rules
//! or none. The `ip` commands are not; each is its own syscall. So the
//! order matters and only one order is safe: routing first, ruleset last.
//! An `ip rule` that matches a mark nothing sets is inert, so a failure
//! half way leaves the machine exactly as it was. The other order stamps
//! packets with a mark that routes nowhere, and traffic the operator
//! believes is in a tunnel goes out in the clear.
//!
//! **The dead-man switch cannot live here.** A countdown thread inside
//! this process is armed by, and dies with, the thing it is protecting:
//! apply from an SSH session, break that session's own path, and systemd
//! tears down the session scope and kills the process group — killing the
//! countdown with the exact event it exists to detect. So the revert is
//! handed to systemd, which is PID 1 and is not going anywhere.
//!
//! **"My session still works" proves nothing.** Every open flow on the
//! host is `established` at the instant the ruleset lands, and the
//! exclusions return early for exactly those. The operator's prompt comes
//! back, the page loads, and none of it touched the policy. Only a NEW
//! connection tests what was just applied, which is why [`apply`] can be
//! given something to dial and reverts on its own if that fails.

use std::fmt::Write as _;
use std::path::{Path as FsPath, PathBuf};
use std::process::Command;

use crate::{Host, Plan, Policy, Refusal, TABLE};

/// Where the record of what is applied lives.
///
/// `/run` is tmpfs, so this disappears on reboot — which is correct,
/// because so does everything it describes. nftables rules and ip rules
/// are not persistent, so a reboot is itself a revert.
pub const STATE: &str = "/run/throughline/applied";

/// The systemd unit that holds the revert.
pub const DEADMAN_UNIT: &str = "throughline-revert";

/// What went wrong.
#[derive(Debug)]
pub enum ApplyError {
    /// The plan should not be applied. Nothing was attempted.
    Refused(Vec<Refusal>),
    /// A command failed, and everything already done has been undone.
    RolledBack { failed: String, stderr: String },
    /// A command failed AND the rollback also failed. The machine is in a
    /// state nobody planned; the remaining steps are listed so a person
    /// can finish by hand.
    Stranded { failed: String, remaining: Vec<String> },
    /// The new connection made after applying did not work, so the policy
    /// was reverted.
    VerificationFailed { target: String, detail: String },
    Io(std::io::Error),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => {
                writeln!(f, "not applied:")?;
                for x in r {
                    writeln!(f, "  - {}", x.explain())?;
                }
                Ok(())
            }
            Self::RolledBack { failed, stderr } => write!(
                f,
                "{failed} failed, so nothing was applied. The machine is as it was.\n  {}",
                stderr.trim()
            ),
            Self::Stranded { failed, remaining } => {
                writeln!(f, "{failed} failed AND the undo failed. Run by hand:")?;
                for c in remaining {
                    writeln!(f, "  {c}")?;
                }
                Ok(())
            }
            Self::VerificationFailed { target, detail } => write!(
                f,
                "applied, then could not open a new connection to {target} ({detail}), \
                 so it was reverted. An existing session surviving would have proved \
                 nothing: every open flow is excluded by construction."
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for ApplyError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// How to apply.
#[derive(Debug, Clone)]
pub struct Options {
    /// Seconds before the policy reverts itself unless confirmed. Zero
    /// disables the switch, which is only sensible somewhere you cannot
    /// be locked out of.
    pub deadman_secs: u32,
    /// `host:port` to open a NEW connection to after applying. The one
    /// check that actually tests the policy.
    pub verify: Option<String>,
    /// Print what would run instead of running it.
    pub dry_run: bool,
    /// Where `nft`, `ip` and `systemd-run` should be run. `None` is this
    /// machine; `Some(name)` runs them inside that network namespace,
    /// which is how the test suite exercises this code for real.
    pub netns: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self { deadman_secs: 120, verify: None, dry_run: false, netns: None }
    }
}

/// What is currently applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// Exactly how to undo it.
    pub revert: Vec<String>,
    /// Whether a dead-man switch is still counting down.
    pub deadman: bool,
}

impl Applied {
    /// The on-disk form: one command per line, `#` for the header.
    #[must_use]
    pub fn serialise(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "# throughline: applied. Each line undoes one thing, in order.");
        let _ = writeln!(s, "# deadman={}", self.deadman);
        for c in &self.revert {
            let _ = writeln!(s, "{c}");
        }
        s
    }

    /// Read it back.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        Self {
            deadman: text.lines().any(|l| l.trim() == "# deadman=true"),
            revert: text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(ToOwned::to_owned)
                .collect(),
        }
    }
}

fn argv(netns: Option<&str>, cmd: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    if let Some(ns) = netns {
        // `nsenter --net`, not `ip netns exec`: the latter also unshares
        // the mount namespace and remounts /sys, which hides
        // /sys/fs/cgroup — and nft resolves every cgroup path when the
        // ruleset loads, so each one fails while being perfectly correct.
        v.push("nsenter".to_owned());
        v.push(format!("--net=/var/run/netns/{ns}"));
    }
    v.extend(cmd.split_whitespace().map(ToOwned::to_owned));
    v
}

fn run(netv: Option<&str>, cmd: &str) -> Result<(), (String, String)> {
    let v = argv(netv, cmd);
    let out = Command::new(&v[0])
        .args(&v[1..])
        .output()
        .map_err(|e| (cmd.to_owned(), e.to_string()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err((cmd.to_owned(), String::from_utf8_lossy(&out.stderr).into_owned()))
    }
}

fn state_path(opts: &Options) -> PathBuf {
    match &opts.netns {
        Some(ns) => PathBuf::from(format!("{STATE}.{ns}")),
        None => PathBuf::from(STATE),
    }
}

/// Apply a plan.
///
/// Refuses outright if the plan should not be applied. Otherwise: routing
/// first, ruleset last, undoing everything already done if any step
/// fails. See the module comment for why that order and no other.
///
/// # Errors
/// See [`ApplyError`]. Every variant except `Stranded` leaves the machine
/// as it was.
pub fn apply(
    policy: &Policy,
    host: &Host,
    plan: &Plan,
    opts: &Options,
) -> Result<Applied, ApplyError> {
    let refusals = plan.preflight(policy, host);
    if !refusals.is_empty() {
        return Err(ApplyError::Refused(refusals));
    }
    let ns = opts.netns.as_deref();

    // Take out whatever is already applied, first.
    //
    // "Apply this policy" means this is now the policy, not "add it to
    // whatever was there". Without this, the second apply re-runs
    // `ip route add` against a table that already has the route, fails
    // with EEXIST, rolls back — and the rollback tears down the FIRST
    // policy's routing while leaving its ruleset loaded. The machine ends
    // up marking packets that route nowhere, under a policy nobody chose.
    // Revising a decision is the second thing anyone does with this tool.
    if !opts.dry_run && state_path(opts).exists() {
        let _ = revert(opts);
    }

    if opts.dry_run {
        for c in &plan.ip {
            println!("{}", argv(ns, c).join(" "));
        }
        println!("{} nft -f - <<'RULES'\n{}RULES", argv(ns, "").join(" "), plan.nft);
        return Ok(Applied { revert: plan.revert.clone(), deadman: false });
    }

    // Routing first. An `ip rule` matching a mark nothing sets does
    // nothing at all, so a failure here leaves the machine untouched.
    let mut done: Vec<String> = Vec::new();
    for (i, cmd) in plan.ip.iter().enumerate() {
        if let Err((failed, stderr)) = run(ns, cmd) {
            undo(ns, &undo_for(plan, i))?;
            return Err(ApplyError::RolledBack { failed, stderr });
        }
        done.push(cmd.clone());
    }

    // The ruleset last: this is the step that makes any of it take
    // effect, and it is the one step that is atomic on its own.
    if let Err((failed, stderr)) = nft_load(ns, &plan.nft) {
        undo(ns, &undo_for(plan, plan.ip.len()))?;
        return Err(ApplyError::RolledBack { failed, stderr });
    }

    let mut applied = Applied { revert: plan.revert.clone(), deadman: false };

    if opts.deadman_secs > 0 {
        arm(ns, &applied.revert, opts.deadman_secs)?;
        applied.deadman = true;
    }
    record(opts, &applied)?;

    // The only check that tests what was just applied.
    if let Some(target) = &opts.verify {
        if let Err(detail) = dial(ns, target) {
            let _ = revert(opts);
            return Err(ApplyError::VerificationFailed { target: target.clone(), detail });
        }
    }
    Ok(applied)
}

fn undo_for(plan: &Plan, ip_steps_done: usize) -> Vec<String> {
    // The revert list is nft-delete first, then two entries per ip step.
    // Undo only what was actually done.
    let mut v = Vec::new();
    if ip_steps_done >= plan.ip.len() {
        v.push(plan.revert[0].clone());
    }
    v.extend(plan.revert[1..].iter().cloned());
    v
}

fn undo(ns: Option<&str>, cmds: &[String]) -> Result<(), ApplyError> {
    let mut left: Vec<String> = Vec::new();
    for c in cmds {
        // Best effort, and keep going: a later step may still be needed
        // even if an earlier one was never applied.
        if run(ns, c).is_err() {
            left.push(c.clone());
        }
    }
    // An undo step failing because the thing was not there is normal, so
    // this is not treated as stranding unless everything failed.
    if !left.is_empty() && left.len() == cmds.len() {
        return Err(ApplyError::Stranded { failed: "rollback".to_owned(), remaining: left });
    }
    Ok(())
}

fn nft_load(ns: Option<&str>, ruleset: &str) -> Result<(), (String, String)> {
    use std::io::Write as _;
    let v = argv(ns, "nft -f -");
    let mut child = Command::new(&v[0])
        .args(&v[1..])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ("nft -f -".to_owned(), e.to_string()))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| ("nft -f -".to_owned(), "no stdin".to_owned()))?
        .write_all(ruleset.as_bytes())
        .map_err(|e| ("nft -f -".to_owned(), e.to_string()))?;
    let out = child
        .wait_with_output()
        .map_err(|e| ("nft -f -".to_owned(), e.to_string()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(("nft -f -".to_owned(), String::from_utf8_lossy(&out.stderr).into_owned()))
    }
}

/// Hand the revert to systemd, on a timer.
fn arm(ns: Option<&str>, revert: &[String], secs: u32) -> Result<(), ApplyError> {
    let _ = disarm(ns);
    let script = revert.join("; ");
    let unit = unit_name(ns);
    let mut v = vec![
        "systemd-run".to_owned(),
        format!("--unit={unit}"),
        format!("--on-active={secs}s"),
        "--timer-property=AccuracySec=1s".to_owned(),
        "--description=Throughline: undo the routing policy unless confirmed".to_owned(),
    ];
    if let Some(n) = ns {
        // The revert has to run in the same network namespace the policy
        // was applied to, and systemd runs it from PID 1's.
        v.push("/usr/bin/nsenter".to_owned());
        v.push(format!("--net=/var/run/netns/{n}"));
    }
    v.push("/bin/sh".to_owned());
    v.push("-c".to_owned());
    v.push(script);
    let out = Command::new(&v[0]).args(&v[1..]).output()?;
    if !out.status.success() {
        return Err(ApplyError::RolledBack {
            failed: "systemd-run (dead-man switch)".to_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(())
}

fn unit_name(ns: Option<&str>) -> String {
    ns.map_or_else(|| DEADMAN_UNIT.to_owned(), |n| format!("{DEADMAN_UNIT}-{n}"))
}

fn disarm(ns: Option<&str>) -> std::io::Result<()> {
    let unit = unit_name(ns);
    let _ = Command::new("systemctl").args(["stop", &format!("{unit}.timer")]).output()?;
    let _ = Command::new("systemctl").args(["reset-failed", &unit]).output();
    Ok(())
}

/// Open a NEW connection, which is the only thing that tests the policy.
fn dial(ns: Option<&str>, target: &str) -> Result<(), String> {
    // Dialled from a child so it can be placed in the right network
    // namespace; `bash`'s /dev/tcp avoids needing a helper binary.
    let v = argv(
        ns,
        &format!("timeout 6 bash -c exec3<>/dev/tcp/{}", target.replace(':', "/")),
    );
    let out = Command::new(&v[0]).args(&v[1..]).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

fn record(opts: &Options, applied: &Applied) -> std::io::Result<()> {
    let p = state_path(opts);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(p, applied.serialise())
}

/// Undo whatever is applied, using the record written when it was.
///
/// # Errors
/// Returns the io error if the record cannot be read or removed.
pub fn revert(opts: &Options) -> Result<Applied, ApplyError> {
    let p = state_path(opts);
    let text = std::fs::read_to_string(&p)?;
    let applied = Applied::parse(&text);
    let ns = opts.netns.as_deref();
    let _ = disarm(ns);
    undo(ns, &applied.revert)?;
    let _ = std::fs::remove_file(&p);
    Ok(applied)
}

/// Cancel the dead-man switch, keeping the policy.
///
/// # Errors
/// Returns the io error if the record cannot be updated.
pub fn confirm(opts: &Options) -> Result<Applied, ApplyError> {
    let p = state_path(opts);
    let mut applied = Applied::parse(&std::fs::read_to_string(&p)?);
    disarm(opts.netns.as_deref())?;
    applied.deadman = false;
    record(opts, &applied)?;
    Ok(applied)
}

/// What the machine says is applied, as opposed to what was planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// A record exists.
    pub recorded: bool,
    /// The nftables table is present.
    pub table_present: bool,
    /// Every ip rule the record expects is present.
    pub rules_present: bool,
    /// A dead-man switch is still counting down.
    pub deadman_armed: bool,
}

impl Status {
    /// A sentence naming which of the states this actually is.
    #[must_use]
    pub fn describe(&self) -> String {
        match (self.recorded, self.table_present, self.rules_present) {
            (false, false, false) => "nothing applied".to_owned(),
            (true, true, true) => {
                if self.deadman_armed {
                    "applied, and reverting shortly unless confirmed".to_owned()
                } else {
                    "applied and confirmed".to_owned()
                }
            }
            // These are the states that matter, and the reason a
            // read-back exists at all: each one is a plan and a kernel
            // that disagree, and none of them announces itself.
            (true, false, true) => "HALF APPLIED: the routing is in place but the ruleset \
                 is gone. Something flushed nftables — /etc/nftables.conf begins with \
                 `flush ruleset` on many hosts, so a reload of the baseline firewall \
                 does exactly this. Traffic is taking the ordinary route."
                .to_owned(),
            (true, true, false) => "HALF APPLIED: the ruleset is marking packets but the \
                 routing rules are gone, so the marks lead nowhere."
                .to_owned(),
            (false, true, _) | (false, _, true) => "SOMETHING IS APPLIED THAT NOTHING \
                 RECORDED. Another tool, or a run whose record was lost."
                .to_owned(),
            (true, false, false) => "a record exists but nothing is applied; it was \
                 probably reverted by hand."
                .to_owned(),
        }
    }
}

/// Compare the record against the kernel.
#[must_use]
pub fn status(opts: &Options) -> Status {
    let ns = opts.netns.as_deref();
    let text = std::fs::read_to_string(state_path(opts)).unwrap_or_default();
    let recorded = !text.trim().is_empty();
    let applied = Applied::parse(&text);

    let table_present = capture(ns, "nft list tables")
        .is_some_and(|o| o.lines().any(|l| l.contains(&format!("inet {TABLE}"))));

    let want: Vec<&String> = applied
        .revert
        .iter()
        .filter(|c| c.starts_with("ip rule del"))
        .collect();
    let shown = capture(ns, "ip rule show").unwrap_or_default();
    let rules_present = !want.is_empty()
        && want.iter().all(|c| {
            c.split_whitespace()
                .nth(4)
                .is_some_and(|mark| shown.contains(mark.trim_start_matches("0x")))
        });

    let deadman_armed = Command::new("systemctl")
        .args(["is-active", &format!("{}.timer", unit_name(ns))])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "active");

    Status { recorded, table_present, rules_present, deadman_armed }
}

fn capture(ns: Option<&str>, cmd: &str) -> Option<String> {
    let v = argv(ns, cmd);
    let out = Command::new(&v[0]).args(&v[1..]).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Whether this host's baseline firewall would wipe the policy on reload.
///
/// A great many distributions ship `/etc/nftables.conf` beginning with
/// `flush ruleset`, so `systemctl reload nftables` — or a config
/// management run, or anyone editing the baseline — deletes our table
/// while the ip rules and routing tables survive untouched. That is the
/// half-applied state above, and it arrives silently.
#[must_use]
pub fn baseline_flushes(conf: &FsPath) -> bool {
    std::fs::read_to_string(conf).is_ok_and(|t| {
        t.lines()
            .map(str::trim)
            .any(|l| l.starts_with("flush ruleset") || l.starts_with("flush table"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_round_trips() {
        let a = Applied {
            revert: vec![
                "nft delete table inet throughline".into(),
                "ip route flush table 7401".into(),
            ],
            deadman: true,
        };
        let back = Applied::parse(&a.serialise());
        assert_eq!(back, a);
        let off = Applied { deadman: false, ..a.clone() };
        assert_eq!(Applied::parse(&off.serialise()), off);
    }

    #[test]
    fn a_namespace_run_uses_nsenter_and_not_ip_netns_exec() {
        // `ip netns exec` remounts /sys and hides /sys/fs/cgroup, and nft
        // resolves every cgroup path when the ruleset loads — so each one
        // fails while being perfectly correct.
        let v = argv(Some("tl-app"), "nft -f -");
        assert_eq!(v[0], "nsenter");
        assert_eq!(v[1], "--net=/var/run/netns/tl-app");
        assert_eq!(argv(None, "nft list tables")[0], "nft");
    }

    #[test]
    fn a_partial_apply_undoes_only_what_was_actually_done() {
        // The ruleset is loaded last, so if it fails the table was never
        // created and deleting it is not part of the undo.
        let plan = Plan {
            ip: vec!["a".into(), "b".into()],
            revert: vec![
                "nft delete table inet throughline".into(),
                "undo-a".into(),
                "undo-b".into(),
            ],
            ..Plan::default()
        };
        assert_eq!(undo_for(&plan, 2), vec!["nft delete table inet throughline", "undo-a", "undo-b"]);
        assert_eq!(undo_for(&plan, 1), vec!["undo-a", "undo-b"]);
        assert_eq!(undo_for(&plan, 0), vec!["undo-a", "undo-b"]);
    }

    #[test]
    fn every_disagreement_between_plan_and_kernel_has_a_name() {
        // The point of a read-back: each of these is a real state the
        // machine can be in, and not one of them announces itself.
        let s = |r, t, u| Status { recorded: r, table_present: t, rules_present: u, deadman_armed: false };
        assert_eq!(s(false, false, false).describe(), "nothing applied");
        assert!(s(true, true, true).describe().starts_with("applied and confirmed"));
        assert!(s(true, false, true).describe().contains("flush ruleset"));
        assert!(s(true, true, false).describe().contains("marks lead nowhere"));
        assert!(s(false, true, false).describe().contains("NOTHING RECORDED"));
        assert!(s(true, false, false).describe().contains("reverted by hand"));
        let armed = Status { deadman_armed: true, ..s(true, true, true) };
        assert!(armed.describe().contains("unless confirmed"));
    }

    #[test]
    fn a_baseline_that_flushes_is_detected() {
        let dir = std::env::temp_dir().join(format!("tl-nft-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("nftables.conf");
        std::fs::write(&f, "#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {}\n").unwrap();
        assert!(baseline_flushes(&f));
        std::fs::write(&f, "#!/usr/sbin/nft -f\ntable inet filter {}\n").unwrap();
        assert!(!baseline_flushes(&f));
        assert!(!baseline_flushes(FsPath::new("/nonexistent")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_namespaced_run_keeps_its_own_record_and_its_own_timer() {
        // So a test suite cannot revert the host's policy, or be reverted
        // by it.
        let ns = Options { netns: Some("tl-app".into()), ..Options::default() };
        assert_ne!(state_path(&ns), state_path(&Options::default()));
        assert_eq!(unit_name(Some("tl-app")), "throughline-revert-tl-app");
        assert_eq!(unit_name(None), DEADMAN_UNIT);
    }

    #[test]
    fn a_second_apply_replaces_the_first_rather_than_colliding_with_it() {
        // Proven for real in scripts/netns-test.sh; this pins the reason.
        // `ip rule add` happily creates a duplicate and `ip route add`
        // fails with EEXIST, so the second apply rolled back — and the
        // rollback dismantled the FIRST policy's routing while its ruleset
        // stayed loaded. `status()` named that state exactly:
        let half = Status {
            recorded: true,
            table_present: true,
            rules_present: false,
            deadman_armed: false,
        };
        assert!(half.describe().contains("marks lead nowhere"));
    }

    #[test]
    fn the_default_leaves_the_switch_armed() {
        // Defaulting to no dead-man switch would be a convenience that
        // costs a machine.
        assert!(Options::default().deadman_secs >= 60);
        assert!(!Options::default().dry_run);
    }
}
