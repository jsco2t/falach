//! Rejection-sampling primitive shared by [`password`](crate::password)
//! and [`passphrase`](crate::passphrase).
//!
//! [`ByteCursor`] walks a precomputed byte buffer four bytes at a time
//! and produces uniform random integers in arbitrary `[0, range)`
//! windows via standard 32-bit rejection sampling. The buffer's
//! provenance — production CSPRNG vs deterministic test stream — is
//! the caller's concern; the cursor only cares that it has enough
//! bytes to draw from.

use crate::error::GenError;

/// Number of random bytes pulled per index draw. Four bytes feed the
/// `u32` rejection-sampling helper.
pub(crate) const BYTES_PER_DRAW: usize = 4;

/// Walks a byte buffer, consuming 4 bytes per uniform-index draw and
/// performing rejection sampling to avoid modulo bias.
pub(crate) struct ByteCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn next_u32(&mut self) -> Result<u32, GenError> {
        if self.pos + BYTES_PER_DRAW > self.bytes.len() {
            return Err(GenError::Csprng(getrandom::Error::UNEXPECTED));
        }
        let chunk: [u8; BYTES_PER_DRAW] = self.bytes[self.pos..self.pos + BYTES_PER_DRAW]
            .try_into()
            .expect("slice length checked above");
        self.pos += BYTES_PER_DRAW;
        Ok(u32::from_le_bytes(chunk))
    }

    /// Uniform random integer in `[0, range)`, via rejection sampling.
    ///
    /// `range` is taken as `usize` for caller convenience (lengths of
    /// `Vec<char>` and `&[&str; N]` are `usize`); the rejection math
    /// is done in `u32`. `range == 0` is a programmer error and
    /// panics; callers control the range upstream and never ask for
    /// an empty one.
    pub(crate) fn uniform_index(&mut self, range: usize) -> Result<usize, GenError> {
        assert!(range > 0, "uniform_index called with empty range");
        let range_u32: u32 = range
            .try_into()
            .expect("alphabet / wordlist sizes fit in u32");
        let threshold = u32::MAX - (u32::MAX % range_u32);
        loop {
            let v = self.next_u32()?;
            if v < threshold {
                return Ok((v % range_u32) as usize);
            }
        }
    }
}
