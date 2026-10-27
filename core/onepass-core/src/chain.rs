//! Pinned chain state: what this device has seen of the account's signed,
//! versioned records, so that a store serving an older one is caught.
//!
//! It sits beside `DeviceState` (whose encoding stays as it is), in the
//! `meta` table of a `SyncStore` under the key `chain`. Other stores keep it
//! in memory only: each session then starts from the default, and pins on
//! first use.
//!
//! - `params_epoch`: the highest account params epoch accepted by an unlock
//!   on this device. Params with a lower epoch are refused
//!   (`IntegrityError::ParamsRollback`). The epoch is generic: it is the
//!   counter of the signed account params, bumped by every change of the
//!   params (a master password change today).
//! - `device_list`, `vault_list`: the last signed device list and vault list
//!   accepted (filled by later milestones).
//! - `device_id`: this device's id in the device list, once registered.

use serde::{Deserialize, Serialize};

use crate::{Error, Id, Result};

/// Encoding version, the first byte of `ChainState::encode`.
const VERSION: u8 = 1;

/// A signed list as last accepted: its sequence number and the hash of its
/// signed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    pub seq: u64,
    pub hash: [u8; 32],
}

/// See the module doc.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainState {
    pub params_epoch: u64,
    pub device_list: Option<Seen>,
    pub vault_list: Option<Seen>,
    pub device_id: Option<Id>,
}

impl ChainState {
    /// Version byte, then the postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        // Plain data (integers, options of hashes and ids): cannot fail.
        out.extend(postcard::to_allocvec(self).expect("chain state encodes"));
        out
    }

    /// Decode what `encode` wrote: a known version byte and the whole
    /// buffer, trailing bytes refused (`InvalidFormat("chain state")`).
    pub fn decode(bytes: &[u8]) -> Result<ChainState> {
        let bad = Error::InvalidFormat("chain state");
        match bytes.split_first() {
            Some((&VERSION, body)) => match postcard::take_from_bytes::<ChainState>(body) {
                Ok((state, [])) => Ok(state),
                _ => Err(bad),
            },
            _ => Err(bad),
        }
    }

    /// Remember `epoch` as accepted: the pinned epoch only goes up.
    pub fn accept_params_epoch(&mut self, epoch: u64) {
        self.params_epoch = self.params_epoch.max(epoch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> ChainState {
        ChainState {
            params_epoch: 7,
            device_list: Some(Seen {
                seq: 3,
                hash: [1; 32],
            }),
            vault_list: Some(Seen {
                seq: 9,
                hash: [2; 32],
            }),
            device_id: Some(Id::new()),
        }
    }

    #[test]
    fn round_trip() {
        for s in [ChainState::default(), full()] {
            let bytes = s.encode();
            assert_eq!(bytes[0], VERSION);
            assert_eq!(ChainState::decode(&bytes).unwrap(), s);
        }
    }

    #[test]
    fn decode_is_strict() {
        let bad = Err(Error::InvalidFormat("chain state"));
        let mut bytes = full().encode();
        assert_eq!(ChainState::decode(&[]), bad);
        // Unknown version.
        bytes[0] = 2;
        assert_eq!(ChainState::decode(&bytes), bad);
        // Trailing bytes.
        let mut bytes = full().encode();
        bytes.push(0);
        assert_eq!(ChainState::decode(&bytes), bad);
        // Truncated.
        let bytes = full().encode();
        assert_eq!(ChainState::decode(&bytes[..bytes.len() - 1]), bad);
    }

    #[test]
    fn params_epoch_only_goes_up() {
        let mut s = ChainState::default();
        s.accept_params_epoch(2);
        assert_eq!(s.params_epoch, 2);
        s.accept_params_epoch(1);
        assert_eq!(s.params_epoch, 2);
    }
}
