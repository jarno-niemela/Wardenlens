//! Bit-level reading of H.264 syntax and the AVCC framing (ITU-T H.264 7.3, 7.4.1, 9.1).
//!
//! Pure byte parsing of untrusted camera data: nothing here panics, indexes or allocates more
//! than its input.

/// Why a bit read failed. Never carries input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BitsError {
    /// The data ended inside the syntax element.
    #[error("data is truncated")]
    Truncated,
    /// A value is outside the range the specification allows.
    #[error("value outside its allowed range")]
    OutOfRange,
}

/// Removes emulation prevention bytes (`00 00 03` becomes `00 00`, spec 7.4.1).
#[must_use]
pub fn unescape(escaped: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(escaped.len());
    let mut zeros = 0_u8;
    for &b in escaped {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
        out.push(b);
    }
    out
}

/// MSB-first bit reader over a byte slice. Every read either consumes input or fails.
pub struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    /// A reader at the first bit of `data`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// One bit.
    ///
    /// # Errors
    /// [`BitsError::Truncated`] at the end of the data.
    pub fn bit(&mut self) -> Result<u32, BitsError> {
        let byte = *self.data.get(self.pos / 8).ok_or(BitsError::Truncated)?;
        let shift = 7_u32.saturating_sub(u32::try_from(self.pos % 8).unwrap_or(0));
        self.pos = self.pos.saturating_add(1);
        Ok(u32::from(byte.checked_shr(shift).unwrap_or(0) & 1))
    }

    /// Up to 32 bits as a number.
    ///
    /// # Errors
    /// [`BitsError::OutOfRange`] above 32, or truncated data.
    pub fn bits(&mut self, n: u32) -> Result<u32, BitsError> {
        if n > 32 {
            return Err(BitsError::OutOfRange);
        }
        let mut v = 0_u64;
        for _ in 0..n {
            v = (v << 1) | u64::from(self.bit()?);
        }
        u32::try_from(v).map_err(|_| BitsError::OutOfRange)
    }

    /// Skips up to 32 bits.
    ///
    /// # Errors
    /// As [`Bits::bits`].
    pub fn skip(&mut self, n: u32) -> Result<(), BitsError> {
        self.bits(n).map(drop)
    }

    /// `ue(v)`: Exp-Golomb, at most 31 leading zeros so the value fits in `u32` (spec 9.1).
    ///
    /// # Errors
    /// Truncated data or more than 31 leading zeros.
    pub fn ue(&mut self) -> Result<u32, BitsError> {
        let mut zeros = 0_u32;
        while self.bit()? == 0 {
            zeros = zeros.saturating_add(1);
            if zeros > 31 {
                return Err(BitsError::OutOfRange);
            }
        }
        let suffix = u64::from(self.bits(zeros)?);
        let base = (1_u64 << zeros).saturating_sub(1);
        u32::try_from(base.saturating_add(suffix)).map_err(|_| BitsError::OutOfRange)
    }

    /// `ue(v)` that must not exceed `max`.
    ///
    /// # Errors
    /// As [`Bits::ue`], or [`BitsError::OutOfRange`] above `max`.
    pub fn ue_max(&mut self, max: u32) -> Result<u32, BitsError> {
        let v = self.ue()?;
        if v > max {
            return Err(BitsError::OutOfRange);
        }
        Ok(v)
    }

    /// `se(v)`: the signed mapping of `ue(v)` (spec 9.1.1), only needed to skip the value.
    ///
    /// # Errors
    /// As [`Bits::ue`].
    pub fn se(&mut self) -> Result<i64, BitsError> {
        let k = i64::from(self.ue()?);
        let magnitude = k.saturating_add(1) / 2;
        Ok(if k % 2 == 1 {
            magnitude
        } else {
            magnitude.saturating_neg()
        })
    }

    /// One bit as a flag.
    ///
    /// # Errors
    /// As [`Bits::bit`].
    pub fn flag(&mut self) -> Result<bool, BitsError> {
        self.bit().map(|b| b == 1)
    }
}
