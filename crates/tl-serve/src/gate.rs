//! Who is allowed to change the machine from the browser.
//!
//! Reading is different from writing here, and the difference is not a
//! matter of degree. The read endpoints answer questions about this host
//! to anything that can reach loopback and passes the `Host` check. The
//! write endpoints change the machine's routing as root.
//!
//! The `Host` check stops DNS rebinding, which is the attack that makes a
//! loopback server reachable from the internet. It is a good check and it
//! is not the only thing standing between a web page and this machine's
//! firewall. So the write endpoints want proof of something a browser
//! cannot have on its own: access to the terminal the server was started
//! from, where the token is printed and nowhere else.
//!
//! That is the whole claim. It is not a password — anyone who can read
//! that terminal can already run `tl-plan` directly. It is a statement
//! that the request came from the person sitting at the machine rather
//! than from a page that merely reached it.

/// A one-per-process token, printed on the terminal at startup.
#[derive(Debug, Clone)]
pub struct Gate {
    token: String,
}

impl Gate {
    /// Read 16 bytes from the kernel's random source.
    ///
    /// Falls back to refusing every write rather than to a weak token: a
    /// machine that cannot produce randomness should not be handed a
    /// guessable key to its own routing.
    #[must_use]
    pub fn new() -> Self {
        let mut buf = [0u8; 16];
        let token = match read_exact_random(&mut buf) {
            Ok(()) => hex(&buf),
            Err(_) => String::new(),
        };
        Self { token }
    }

    /// Build from a known value. Tests only, and `cfg(test)` so a fixed
    /// token cannot be reached from a running server by accident.
    #[cfg(test)]
    #[must_use]
    pub fn with_token(token: &str) -> Self {
        Self {
            token: token.to_owned(),
        }
    }

    /// The token, for printing once at startup.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Whether this request may change the machine.
    ///
    /// An empty configured token never matches anything, so a server that
    /// could not read randomness refuses every write instead of accepting
    /// every write.
    #[must_use]
    pub fn allows(&self, presented: Option<&str>) -> bool {
        let Some(p) = presented else { return false };
        if self.token.is_empty() || p.len() != self.token.len() {
            return false;
        }
        // Constant time in the length of the token. A timing oracle on a
        // loopback socket is a stretch, but the correct comparison is not
        // harder to write than the incorrect one.
        let mut diff = 0u8;
        for (a, b) in self.token.bytes().zip(p.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

fn read_exact_random(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_token_is_long_and_different_every_time() {
        let a = Gate::new();
        let b = Gate::new();
        assert_eq!(a.token().len(), 32, "128 bits of hex");
        assert_ne!(a.token(), b.token());
        assert!(a.token().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn only_the_exact_token_is_allowed() {
        let g = Gate::with_token("abc123");
        assert!(g.allows(Some("abc123")));
        assert!(!g.allows(Some("abc124")));
        assert!(!g.allows(Some("abc12")), "a prefix is not the token");
        assert!(!g.allows(Some("abc1234")));
        assert!(!g.allows(Some("")));
        assert!(!g.allows(None), "absent is not allowed");
    }

    #[test]
    fn a_server_without_randomness_refuses_every_write() {
        // The failure direction matters: an empty token must mean "no",
        // not "anything", and an empty PRESENTED token must not match it.
        let g = Gate::with_token("");
        assert!(!g.allows(Some("")));
        assert!(!g.allows(Some("anything")));
        assert!(!g.allows(None));
    }
}
