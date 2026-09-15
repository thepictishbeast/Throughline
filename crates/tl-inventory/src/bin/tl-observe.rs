//! Print what this machine is talking to, as JSON, and stop.
//!
//! This is the seam between the part that reads a machine and the part
//! that draws it. The front end runs on a laptop with a display; the
//! machine being read may be a headless server on the other end of an
//! SSH connection. So the contract between them is a program that prints
//! JSON and exits — not a library, not a daemon, not a socket.
//!
//! That shape is the whole reason it works remotely:
//!
//! ```sh
//! ssh someserver tl-observe | the-front-end
//! ```
//!
//! No port is opened, nothing is left running, and the credential is
//! SSH's rather than one this tool invented. The previous attempt was a
//! web server bound to loopback, which could not be reached from the
//! phone its author administers from, and had to grow a token of its own
//! to be safe. This has neither problem because it is not a server.
//!
//! The output always begins with the visibility assessment, because an
//! empty `flows` array means nothing until you know whether the kernel
//! would have told us. See `visibility.rs`.

use std::path::Path;

use tl_inventory::ports::EphemeralPorts;
use tl_inventory::services::ServiceNames;
use tl_inventory::snapshot;
use tl_inventory::visibility;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{HELP}");
        return;
    }

    // An override exists so the whole tool can be pointed at a captured
    // /proc tree. Every parser in this crate is already tested that way;
    // being able to do it from the command line means a bug report can
    // arrive as a directory rather than as a description.
    let root = args
        .iter()
        .position(|a| a == "--proc")
        .and_then(|i| args.get(i + 1))
        .map_or_else(|| Path::new("/proc").to_owned(), Into::into);

    let flows = snapshot::collect(&root);
    let attributed = flows.iter().filter(|f| f.holder.is_some()).count();
    let sight = visibility::assess(&root, flows.len(), attributed);

    // Deliberately not a failure. A machine that will not show its
    // socket tables still has a truthful answer to give about itself,
    // and that answer is the first field of the document.
    let services = std::env::var("TL_SERVICES").unwrap_or_else(|_| "/etc/services".to_owned());
    let names = ServiceNames::load(Path::new(&services));
    let ports = EphemeralPorts::load(&root);
    println!("{}", snapshot::to_json(&flows, &names, ports, &sight));

    // The exit status carries the one bit a shell pipeline can act on
    // without parsing: whether the reading can be believed.
    if !sight.sight.can_be_trusted() {
        eprintln!("{}", sight.headline());
        eprintln!("{}", sight.evidence);
        if let Some(r) = &sight.remedy {
            eprintln!("{r}");
        }
        std::process::exit(2);
    }
}

const HELP: &str = "\
tl-observe — print this machine's connections as JSON

USAGE:
    tl-observe [--proc <dir>]
    ssh <host> tl-observe        # the intended use: read a remote machine

OPTIONS:
    --proc <dir>    read a captured /proc tree instead of this machine's
    -h, --help      this text

EXIT STATUS:
    0   the reading can be believed
    2   the machine is withholding its socket tables, or there are none
        to read. The JSON is still printed and still says so; the status
        is for a shell that will not parse it.
";
