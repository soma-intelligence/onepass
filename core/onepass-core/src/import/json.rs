//! Lenient JSON lists shared by the JSON importers (1PUX, CXF): elements
//! that do not decode are reported, never silently dropped.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// A JSON array of `T`: `null` or any other type is empty, and an element
/// that does not decode is left out and counted so that the caller can
/// report it.
pub(crate) struct Lenient<T> {
    pub(crate) list: Vec<T>,
    pub(crate) dropped: u32,
}

impl<T> Default for Lenient<T> {
    fn default() -> Self {
        Lenient {
            list: Vec::new(),
            dropped: 0,
        }
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Lenient<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let mut out = Lenient::default();
        if let Value::Array(a) = Value::deserialize(d)? {
            for v in a {
                match serde_json::from_value(v) {
                    Ok(t) => out.list.push(t),
                    Err(_) => out.dropped = out.dropped.saturating_add(1),
                }
            }
        }
        Ok(out)
    }
}

/// A JSON array of `T` that keeps the position of every element: one that
/// does not decode is `None`.
pub(crate) struct Slots<T>(pub(crate) Vec<Option<T>>);

impl<T> Default for Slots<T> {
    fn default() -> Self {
        Slots(Vec::new())
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Slots<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(Slots(match Value::deserialize(d)? {
            Value::Array(a) => a
                .into_iter()
                .map(|v| serde_json::from_value(v).ok())
                .collect(),
            _ => Vec::new(),
        }))
    }
}
