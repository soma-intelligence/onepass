//! Serde helpers for byte fields.
//!
//! The wire format is postcard, which is not human readable: there each helper
//! writes exactly what serde's own impls write (a fixed array is a tuple of
//! `u8`, a `Vec<u8>` a sequence of `u8`), so the postcard bytes are unchanged.
//! A human readable serializer (the `serde-wasm-bindgen` one of the WebAssembly
//! build) gets `serialize_bytes` instead, so JavaScript sees `Uint8Array` and
//! never an ambiguous array of numbers. Serde has no impl for `[u8; 64]`, so
//! signatures need the fixed helper anyway.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeTuple, Serializer};

/// Owned fixed array, for the list helpers.
pub(crate) struct Fixed<const N: usize>(pub [u8; N]);

/// Borrowed fixed array, for the list helpers.
pub(crate) struct FixedRef<'a, const N: usize>(pub &'a [u8; N]);

impl<const N: usize> Serialize for FixedRef<'_, N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        fixed::serialize(self.0, s)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Fixed<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        fixed::deserialize(d).map(Fixed)
    }
}

struct VecRef<'a>(&'a [u8]);

impl Serialize for VecRef<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        vec::serialize(self.0, s)
    }
}

struct Owned(Vec<u8>);

impl<'de> Deserialize<'de> for Owned {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        vec::deserialize(d).map(Owned)
    }
}

struct FixedVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for FixedVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{N} bytes")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<[u8; N], E> {
        v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<[u8; N], E> {
        self.visit_bytes(&v)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; N], A::Error> {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        if seq.next_element::<u8>()?.is_some() {
            return Err(de::Error::invalid_length(N + 1, &self));
        }
        Ok(out)
    }
}

struct VecVisitor;

impl<'de> Visitor<'de> for VecVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bytes")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
        Ok(v)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
        let mut out = Vec::new();
        while let Some(b) = seq.next_element()? {
            out.push(b);
        }
        Ok(out)
    }
}

/// `[u8; N]`.
pub(crate) mod fixed {
    use super::*;

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            return s.serialize_bytes(v);
        }
        let mut t = s.serialize_tuple(N)?;
        for b in v {
            t.serialize_element(b)?;
        }
        t.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        if d.is_human_readable() {
            d.deserialize_bytes(FixedVisitor::<N>)
        } else {
            d.deserialize_tuple(N, FixedVisitor::<N>)
        }
    }
}

/// `Vec<u8>`.
pub(crate) mod vec {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_bytes(v)
        } else {
            s.collect_seq(v)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        if d.is_human_readable() {
            d.deserialize_byte_buf(VecVisitor)
        } else {
            Vec::<u8>::deserialize(d)
        }
    }
}

/// `Option<Vec<u8>>`.
pub(crate) mod opt_vec {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        v.as_deref().map(VecRef).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Ok(Option::<Owned>::deserialize(d)?.map(|o| o.0))
    }
}

/// `Option<[u8; N]>`.
pub(crate) mod opt_fixed {
    use super::*;

    pub fn serialize<S: Serializer, const N: usize>(
        v: &Option<[u8; N]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        v.as_ref().map(FixedRef).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<Option<[u8; N]>, D::Error> {
        Ok(Option::<Fixed<N>>::deserialize(d)?.map(|f| f.0))
    }
}

/// `Vec<[u8; N]>`.
pub(crate) mod fixed_list {
    use super::*;

    pub fn serialize<S: Serializer, const N: usize>(
        v: &[[u8; N]],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(FixedRef))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<Vec<[u8; N]>, D::Error> {
        Ok(Vec::<Fixed<N>>::deserialize(d)?
            .into_iter()
            .map(|f| f.0)
            .collect())
    }
}

/// `Vec<([u8; N], T)>`.
pub(crate) mod fixed_pairs {
    use super::*;

    pub fn serialize<S: Serializer, T: Serialize, const N: usize>(
        v: &[([u8; N], T)],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|(h, t)| (FixedRef(h), t)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>, const N: usize>(
        d: D,
    ) -> Result<Vec<([u8; N], T)>, D::Error> {
        Ok(Vec::<(Fixed<N>, T)>::deserialize(d)?
            .into_iter()
            .map(|(h, t)| (h.0, t))
            .collect())
    }
}
