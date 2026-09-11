//! Read-only inventory of what is talking to the network on this host.
//!
//! The claim this crate has to earn is "everything". A view that silently
//! drops rows is worse than no view, because it is trusted. So: every
//! parser skips the row it cannot read rather than the table, every
//! fallible step degrades to a less specific answer rather than to
//! nothing, and the tests run against captured kernel output rather than
//! whatever the machine running them happens to be doing.
//!
//! Nothing here writes, opens a socket, or changes a route.

pub mod proc_net;
pub mod procs;
pub mod snapshot;
