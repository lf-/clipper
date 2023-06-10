//! A reimplementation of the `hexdump` crate with no_std support.
#![cfg_attr(not(test), no_std)]

/// An object you can use to dump bytes incrementally without allocation
pub struct HexDumper<'a> {
    bytes: &'a [u8],
}

impl<'a> core::fmt::Display for HexDumper<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut pos: usize = 0;
        for line in self.bytes.chunks(0x10) {
            write!(f, "{:04x}: ", pos)?;
            let mut it = line.chunks(2).peekable();
            let mut pad = 42;

            while let Some(group) = it.next() {
                for b in group {
                    pad -= 2;
                    write!(f, "{:02x}", b)?;
                }
                if it.peek().is_some() {
                    pad -= 1;
                    write!(f, " ")?;
                }
            }
            for _ in 0..pad {
                write!(f, " ")?;
            }

            for c in line {
                let printable = c.is_ascii_punctuation() || c.is_ascii_alphanumeric();
                if printable {
                    write!(f, "{}", *c as char)?;
                } else {
                    write!(f, ".")?;
                }
            }
            pos += 0x10;
            write!(f, "\n")?;
        }
        Ok(())
    }
}

impl HexDumper<'_> {
    /// Makes a new hex dump iterator
    pub fn new(bytes: &[u8]) -> HexDumper {
        HexDumper { bytes }
    }
}

#[cfg(test)]
mod tests {
    use crate::HexDumper;

    #[test]
    fn it_works() {
        let bytes = *b"ABCDE";
        let outp = "0000: 4142 4344 45                              ABCDE\n";
        assert_eq!(outp, format!("{}", HexDumper::new(&bytes)));

        let mut bytes = [0u8; 18];
        for i in 0u8..=17 {
            bytes[i as usize] = i;
        }
        let outp = "0000: 0001 0203 0405 0607 0809 0a0b 0c0d 0e0f   ................\n\
                         0010: 1011                                      ..\n";
        assert_eq!(outp, format!("{}", HexDumper::new(&bytes)));

        let outp = "0000: 00                                        .\n";
        assert_eq!(outp, format!("{}", HexDumper::new(&bytes[..1])))
    }
}
