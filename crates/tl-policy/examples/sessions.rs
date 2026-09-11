//! Who does this host think is administering it, and on what evidence?
use std::path::Path as FsPath;
fn main() {
    for c in tl_policy::probe::admin_candidates(FsPath::new("/proc")) {
        println!(
            "{} {}:{}  [{}]\n    {}",
            if c.likely { "LIKELY YOU " } else { "UNCONFIRMED" },
            c.peer, c.port, c.holder, c.evidence
        );
    }
}
