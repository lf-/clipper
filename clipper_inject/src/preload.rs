//! Traditional LD_PRELOAD hooks. NOTE: This is actively somewhat broken on
//! openssl, because they use -Bsymbolic so all calls to openssl functions from
//! within openssl are statically bound and don't invoke the hooks (!).
//!
//! Now rewritten as Frida stuff.
//! FIXME: figure out what to do with this Show thing
use std::fmt;

struct Show<'a>(&'a [u8]);
impl<'a> fmt::Display for Show<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;
        for &ch in self.0 {
            for part in std::ascii::escape_default(ch) {
                fmt::Write::write_char(f, part as char)?;
            }
        }
        write!(f, "\"")
    }
}
