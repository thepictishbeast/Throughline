//! Cross-check the parser against the live kernel.
//!
//! Not a unit test: it reads this machine, so it belongs outside the suite.
//! But it is the check that matters — a parser that passes fixtures and
//! disagrees with the kernel is exactly the failure this tool cannot have.
use tl_inventory::proc_net::{Proto, parse_table};

fn main() {
    let mut total = 0usize;
    for p in [Proto::Tcp, Proto::Tcp6, Proto::Udp, Proto::Udp6] {
        let text = std::fs::read_to_string(p.proc_file()).unwrap_or_default();
        let rows = parse_table(p, &text);
        // Every non-header line must have produced a row. A silent drop is
        // the failure mode; count it rather than trusting it.
        let data_lines = text
            .lines()
            .filter(|l| l.split_whitespace().next().is_some_and(|f| f.ends_with(':')))
            .count();
        println!(
            "{:>5}: {:>4} data lines -> {:>4} parsed{}",
            p.label(),
            data_lines,
            rows.len(),
            if data_lines == rows.len() { "" } else { "   *** DROPPED ROWS" }
        );
        total += rows.len();
        for s in rows.iter().filter(|s| s.has_peer()).take(3) {
            println!(
                "        {} {}:{} -> {}:{}  inode={}",
                s.state, s.local_addr, s.local_port, s.remote_addr, s.remote_port, s.inode
            );
        }
    }
    println!("total sockets parsed: {total}");
}
