// SPDX-License-Identifier: MIT OR Apache-2.0

//! The house CCB primitive grammar, as `sofi::wire` uses it.
//!
//! | Primitive | Bytes |
//! |---|---|
//! | envelope | `u16_be(class) ‖ u16_be(schema)` — every object starts with it |
//! | `u8` / `u16` / `u32` | fixed width, big-endian |
//! | `digest32` | exactly 32 raw bytes, no prefix |
//! | `bytes` | `u32_be(len) ‖ raw` |
//! | `seq<T>` | `u32_be(count) ‖ T …` |
//! | nested object | its complete CCB, envelope included |
//!
//! Decoders are strict: a wrong class, an unknown schema, truncation, a count
//! outside its table bound and trailing bytes are refused. A refused count is
//! refused before anything is allocated for it.

use core::fmt;

/// Every duel object ships at schema 1.
pub const SCHEMA_V1: u16 = 1;

/// Why bytes are not the canonical encoding of the object asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended inside a field.
    Truncated { field: &'static str },
    /// Bytes remain after the object's last field.
    TrailingBytes { extra: usize },
    /// The envelope names another class.
    WrongClass { expected: u16, got: u16 },
    /// The envelope names a schema this program does not define.
    UnknownSchema { class: u16, schema: u16 },
    /// A count or length is outside the field's table bound.
    Cardinality {
        field: &'static str,
        min: usize,
        max: usize,
        got: usize,
    },
    /// A tag or enumerated value the field table does not define.
    UnknownValue { field: &'static str, value: u32 },
    /// Well-formed bytes whose values break a rule of the object.
    Invalid { what: &'static str },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { field } => write!(f, "input ends inside {field}"),
            Self::TrailingBytes { extra } => write!(f, "{extra} bytes follow the object"),
            Self::WrongClass { expected, got } => {
                write!(f, "class {got:#06x} where {expected:#06x} belongs")
            }
            Self::UnknownSchema { class, schema } => {
                write!(f, "class {class:#06x} has no schema {schema}")
            }
            Self::Cardinality {
                field,
                min,
                max,
                got,
            } => write!(f, "{field}: {got} elements, allowed {min}..={max}"),
            Self::UnknownValue { field, value } => {
                write!(f, "{field}: {value} is not a defined value")
            }
            Self::Invalid { what } => write!(f, "{what}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Appends canonical primitives.
#[derive(Debug, Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// A writer that starts with the object's envelope.
    pub fn object(class: u16) -> Self {
        let mut w = Self { out: Vec::new() };
        w.u16(class);
        w.u16(SCHEMA_V1);
        w
    }
    pub fn u8(&mut self, v: u8) {
        self.out.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }
    pub fn digest(&mut self, d: &[u8; 32]) {
        self.out.extend_from_slice(d);
    }
    /// A count. Every count this program writes was bounded by its table, far
    /// below `u32::MAX`; a count that does not fit saturates and the strict
    /// decoder of the same table refuses the result.
    pub fn count(&mut self, n: usize) {
        self.u32(n.min(u32::MAX as usize) as u32);
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.count(b.len());
        self.out.extend_from_slice(b);
    }
    /// A nested object: its complete CCB, envelope included.
    pub fn nested(&mut self, ccb: &[u8]) {
        self.out.extend_from_slice(ccb);
    }
    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Reads canonical primitives; every read is bounds-checked.
#[derive(Debug)]
pub struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    /// Opens an object and checks its envelope.
    pub fn object(b: &'a [u8], class: u16) -> Result<Self, DecodeError> {
        let mut r = Self { b, i: 0 };
        r.envelope(class)?;
        Ok(r)
    }

    fn envelope(&mut self, class: u16) -> Result<(), DecodeError> {
        let got = self.u16("class")?;
        if got != class {
            return Err(DecodeError::WrongClass {
                expected: class,
                got,
            });
        }
        let schema = self.u16("schema")?;
        if schema != SCHEMA_V1 {
            return Err(DecodeError::UnknownSchema { class, schema });
        }
        Ok(())
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], DecodeError> {
        let end = self
            .i
            .checked_add(n)
            .filter(|end| *end <= self.b.len())
            .ok_or(DecodeError::Truncated { field })?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }

    pub fn u8(&mut self, field: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, field)?[0])
    }
    pub fn u16(&mut self, field: &'static str) -> Result<u16, DecodeError> {
        let s = self.take(2, field)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self, field: &'static str) -> Result<u32, DecodeError> {
        let s = self.take(4, field)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn digest(&mut self, field: &'static str) -> Result<[u8; 32], DecodeError> {
        let s = self.take(32, field)?;
        Ok(core::array::from_fn(|k| s[k]))
    }
    /// A count, refused before allocation when outside `min..=max`.
    pub fn count(
        &mut self,
        field: &'static str,
        min: usize,
        max: usize,
    ) -> Result<usize, DecodeError> {
        let n = self.u32(field)? as usize;
        if n < min || n > max {
            return Err(DecodeError::Cardinality {
                field,
                min,
                max,
                got: n,
            });
        }
        Ok(n)
    }
    pub fn bytes(
        &mut self,
        field: &'static str,
        min: usize,
        max: usize,
    ) -> Result<Vec<u8>, DecodeError> {
        let n = self.count(field, min, max)?;
        Ok(self.take(n, field)?.to_vec())
    }
    /// A nested object of `class`: its bytes run to the end of its own
    /// decoder, so the caller passes the decoder.
    pub fn nested<T>(
        &mut self,
        decode: impl FnOnce(&mut Reader<'a>) -> Result<T, DecodeError>,
        class: u16,
    ) -> Result<T, DecodeError> {
        self.envelope(class)?;
        decode(self)
    }
    /// Refuses trailing bytes.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.i != self.b.len() {
            return Err(DecodeError::TrailingBytes {
                extra: self.b.len() - self.i,
            });
        }
        Ok(())
    }
}

/// `BLAKE3(tag ‖ 0x00 ‖ parts…)`, the DSM tagged-hash convention.
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag.as_bytes());
    h.update(&[0u8]);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}
