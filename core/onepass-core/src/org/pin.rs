//! Pinning an organization (spec 5.6, plan B Task 10): the org fingerprint
//! comes from MDM, from a DNS TXT record or on first use (TOFU, confirmed
//! later against the fingerprint an admin reads out). Once pinned, the
//! fingerprint never changes (ruling E2): a server serving the genesis of
//! another org identity, even under the same org id, is refused with
//! `OrgPinMismatch`, never followed.
//!
//! `OrgPin::advance` moves the pin forward: the lineage records first (the
//! list starts at the pinned head), then the rosters. It returns a new pin
//! and leaves `self` as it was.
//!
//! DNS TXT grammar: `v=op1; org=<BASE32_NOPAD of the fingerprint>`, at most
//! 255 bytes, parts split on `;` and trimmed of ASCII whitespace, each part
//! `key=value` (trimmed around `=`, the key not empty), `v=op1` first, `org` exactly once
//! (case-insensitive base32, 52 characters, no padding), unknown keys
//! ignored, any key twice refused, empty parts after the first ignored (a
//! trailing `;`).
//!
//! Local storage: `[ORG_PIN_VERSION] || postcard((source, lineage,
//! roster))`, decoded strictly and re-checked so corrupted storage is an
//! error, never a panic.

use std::collections::BTreeMap;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

use super::lineage::{
    check_identity_pub, check_kem, check_name, check_owners, fork_or_bad_signature,
};
use super::{
    ORG_PIN_VERSION, OrgHeadInfo, OrgLineage, OrgRecordBody, RosterBody, RosterCheckpoint,
    SignedOrgRecord, SignedRoster, accept_first_roster, accept_next_roster, org_fingerprint,
    verify_org_genesis,
};
use crate::lineage::decode_strict_with;
use crate::{Error, IntegrityError, Result, ValidationError};

/// The largest DNS TXT value accepted (one character-string).
const MAX_DNS_TXT_BYTES: usize = 255;
/// `BASE32_NOPAD` of 32 bytes.
const FPR_BASE32_CHARS: usize = 52;
/// The cap on an encoded pin: the roster (at most one org record) plus a
/// lineage of several hundred full generations.
const MAX_ORG_PIN_BYTES: usize = 16 * 1024 * 1024;

/// Where the pinned fingerprint came from. Postcard enum: append-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinSource {
    Mdm,
    Dns,
    /// Trust on first use; `verified` once an admin's fingerprint matched.
    Tofu {
        verified: bool,
    },
}

/// The pinned org: its source, the verified lineage (whose genesis
/// fingerprint is the pin) and the pinned roster, if any yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgPin {
    source: PinSource,
    lineage: OrgLineage,
    roster: Option<RosterBody>,
}

fn bad(what: &'static str) -> Error {
    Error::InvalidFormat(what)
}

fn mismatch() -> Error {
    IntegrityError::OrgPinMismatch.into()
}

fn misuse(field: &str, reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: field.into(),
        reason,
    })
}

/// `BASE32_NOPAD` (uppercase, 52 characters), the DNS TXT encoding.
pub fn fingerprint_base32(fpr: &[u8; 32]) -> String {
    BASE32_NOPAD.encode(fpr)
}

/// `"v=op1; org=" + fingerprint_base32(fpr)`.
pub fn dns_txt_value(fpr: &[u8; 32]) -> String {
    format!("v=op1; org={}", fingerprint_base32(fpr))
}

/// `key=value` trimmed around `=`.
fn key_value(part: &str) -> Option<(&str, &str)> {
    let (k, v) = part.split_once('=')?;
    Some((k.trim_ascii(), v.trim_ascii()))
}

/// Whether the first part of `txt` is `v=op1`: the record is ours.
fn is_op1(txt: &str) -> bool {
    let first = txt.split(';').next().unwrap_or("");
    key_value(first.trim_ascii()) == Some(("v", "op1"))
}

/// The fingerprint of one DNS TXT value (grammar in the module docs). Any
/// refusal is `InvalidFormat`.
pub fn parse_dns_txt(txt: &str) -> Result<[u8; 32]> {
    if txt.len() > MAX_DNS_TXT_BYTES {
        return Err(bad("dns txt size"));
    }
    let mut seen: Vec<&str> = Vec::new();
    let mut org: Option<&str> = None;
    for (i, part) in txt.split(';').map(str::trim_ascii).enumerate() {
        if part.is_empty() && i > 0 {
            continue;
        }
        let (k, v) = key_value(part).ok_or(bad("dns txt part"))?;
        if k.is_empty() {
            return Err(bad("dns txt part"));
        }
        if seen.contains(&k) {
            return Err(bad("dns txt key repeated"));
        }
        seen.push(k);
        match (i, k) {
            (0, "v") if v == "op1" => {}
            (0, _) => return Err(bad("dns txt version")),
            (_, "v") => return Err(bad("dns txt version")),
            (_, "org") => org = Some(v),
            _ => {}
        }
    }
    let org = org.ok_or(bad("dns txt org"))?;
    if org.len() != FPR_BASE32_CHARS {
        return Err(bad("dns txt org"));
    }
    let raw = BASE32_NOPAD
        .decode(org.to_ascii_uppercase().as_bytes())
        .map_err(|_| bad("dns txt org"))?;
    raw.try_into().map_err(|_| bad("dns txt org"))
}

/// The org fingerprint of a domain's TXT records: records whose first part
/// is `v=op1` are ours, the others skipped. None: `NotFound`; a malformed
/// one: `InvalidFormat`; two naming different fingerprints:
/// `OrgPinMismatch`.
pub fn dns_fingerprint(records: &[&str]) -> Result<[u8; 32]> {
    let mut found: Option<[u8; 32]> = None;
    for txt in records.iter().filter(|t| is_op1(t)) {
        let f = parse_dns_txt(txt)?;
        match found {
            Some(prev) if prev != f => return Err(mismatch()),
            _ => found = Some(f),
        }
    }
    found.ok_or(Error::NotFound)
}

/// The fingerprint a genesis record names (no signature checked).
fn genesis_fingerprint(rec: &SignedOrgRecord) -> Option<[u8; 32]> {
    let OrgRecordBody::Genesis(g) = &rec.body else {
        return None;
    };
    Some(org_fingerprint(g))
}

/// Pins the org whose genesis the server served. MDM and DNS need the
/// expected fingerprint (`None` is `Validation`) and it must be the served
/// genesis's (`OrgPinMismatch`); TOFU starts unverified and takes none
/// (`Validation` otherwise). The genesis is decoded strictly and verified
/// (identity signature, owner quorum) before any comparison.
pub fn pin_org(
    source: PinSource,
    expected_fpr: Option<[u8; 32]>,
    served_genesis: &[u8],
) -> Result<OrgPin> {
    match (source, expected_fpr) {
        (PinSource::Mdm | PinSource::Dns, None) => {
            return Err(misuse(
                "expected_fpr",
                "MDM and DNS pins need a fingerprint",
            ));
        }
        (PinSource::Tofu { verified: true }, _) => {
            return Err(misuse("source", "a TOFU pin starts unverified"));
        }
        (PinSource::Tofu { .. }, Some(_)) => {
            return Err(misuse("expected_fpr", "a TOFU pin takes no fingerprint"));
        }
        _ => {}
    }
    let rec = SignedOrgRecord::decode(served_genesis)?;
    let lineage = verify_org_genesis(&rec)?;
    if let Some(f) = expected_fpr
        && f != lineage.fingerprint
    {
        return Err(mismatch());
    }
    Ok(OrgPin {
        source,
        lineage,
        roster: None,
    })
}

/// The roster checkpoints of the `OwnersChanged` generations (X17), with
/// the generation that carries each; seq 0 (no roster yet) left out.
fn checkpoints(lineage: &OrgLineage) -> Vec<(u64, RosterCheckpoint)> {
    lineage
        .heads
        .iter()
        .filter_map(|h| {
            h.roster_checkpoint
                .filter(|c| c.seq > 0)
                .map(|c| (h.generation, c))
        })
        .collect()
}

/// A roster at the seq of a checkpoint must have its hash, else
/// `OrgRosterFork` (X17).
fn check_checkpoints(lineage: &OrgLineage, roster: &RosterBody) -> Result<()> {
    let h = roster.hash();
    if checkpoints(lineage)
        .iter()
        .any(|(_, c)| c.seq == roster.seq && c.hash != h)
    {
        return Err(IntegrityError::OrgRosterFork.into());
    }
    Ok(())
}

/// The rosters after `pinned`, one by one (X17). A roster at or below the
/// checkpoint of an `OwnersChanged` is judged under the lineage up to the
/// generation before the first such change whose checkpoint covers it, a
/// later one under the whole lineage. Every roster at a checkpoint seq
/// must have its hash (`OrgRosterFork`). A roster judged under an older
/// generation is kept only if this chain reaches the checkpoint that
/// covered it: else `NotFound` and nothing is kept, so a forged roster at
/// the frontier never enters a pin. A repeated roster is a rollback.
fn accept_after(
    lineage: &OrgLineage,
    pinned: &RosterBody,
    chain: &[SignedRoster],
) -> Result<RosterBody> {
    let cps = checkpoints(lineage);
    let mut older: BTreeMap<u64, OrgLineage> = BTreeMap::new();
    let mut needed = 0u64;
    let mut cur = pinned.clone();
    for rec in chain {
        let seq = rec.body.seq;
        let judge = match cps.iter().find(|(_, c)| c.seq >= seq) {
            Some((g, c)) => {
                needed = needed.max(c.seq);
                &*older.entry(*g).or_insert_with(|| {
                    let mut l = lineage.clone();
                    // `g >= 1`: the genesis carries no checkpoint.
                    l.heads.truncate(*g as usize);
                    l
                })
            }
            None => lineage,
        };
        if seq <= cur.seq {
            accept_next_roster(judge, &cur, rec)?;
            return Err(IntegrityError::OrgRosterRollback.into());
        }
        cur = accept_next_roster(judge, &cur, rec)?;
        check_checkpoints(lineage, &cur)?;
    }
    if cur.seq < needed {
        return Err(Error::NotFound);
    }
    Ok(cur)
}

impl OrgPin {
    /// The pinned org fingerprint (the genesis's, for good).
    pub fn fingerprint(&self) -> [u8; 32] {
        self.lineage.fingerprint
    }

    pub fn source(&self) -> PinSource {
        self.source
    }

    pub fn lineage(&self) -> &OrgLineage {
        &self.lineage
    }

    /// `lineage().head()`.
    pub fn head(&self) -> &OrgHeadInfo {
        self.lineage.head()
    }

    pub fn roster(&self) -> Option<&RosterBody> {
        self.roster.as_ref()
    }

    pub fn roster_seq(&self) -> Option<u64> {
        self.roster.as_ref().map(|r| r.seq)
    }

    /// The genesis the server serves now: decoded, verified, its
    /// fingerprint the pinned one (`OrgPinMismatch`) and its hash the
    /// pinned genesis's (`OrgLineageFork`).
    pub fn check_served_genesis(&self, served: &[u8]) -> Result<()> {
        let rec = SignedOrgRecord::decode(served)?;
        let l = verify_org_genesis(&rec)?;
        if l.fingerprint != self.fingerprint() {
            return Err(mismatch());
        }
        if l.heads[0].hash != self.lineage.heads[0].hash {
            return Err(IntegrityError::OrgLineageFork.into());
        }
        Ok(())
    }

    /// The pin moved forward by what the server returned
    /// (`OrgStore::lineage_from`, `OrgStore::roster`: `(generation or seq,
    /// record)` pairs, the key matching the record and the keys strictly
    /// increasing, or `InvalidFormat`).
    ///
    /// Lineage first: the first record must be the pinned head (a genesis
    /// of another fingerprint `OrgPinMismatch`, an empty list or another
    /// generation `OrgLineageRollback`, the same generation with another
    /// hash `OrgLineageFork`), then each record is applied and must move
    /// the head forward. Rosters next: with none pinned,
    /// `accept_first_roster` on the list; else the leading entries at or
    /// below the pinned seq are checked against the pinned chain (same
    /// hash ignored, another hash `OrgRosterFork`, as far as the hashes
    /// link back), a list topping out below the pinned seq is
    /// `OrgRosterRollback`, the rest is accepted roster by roster
    /// (`accept_next_roster`) under the roster checkpoints of the lineage
    /// (X17, `accept_after`). The pinned roster must match any checkpoint
    /// at its seq (`OrgRosterFork`). An empty roster list keeps the
    /// roster. Source and fingerprint never change.
    pub fn advance(
        &self,
        lineage_records: &[(u64, Vec<u8>)],
        rosters: &[(u64, Vec<u8>)],
    ) -> Result<OrgPin> {
        let lineage = self.advance_lineage(lineage_records)?;
        let roster = self.advance_roster(&lineage, rosters)?;
        let out = OrgPin {
            source: self.source,
            lineage,
            roster,
        };
        if out.encoded_len() > MAX_ORG_PIN_BYTES {
            return Err(bad("org pin size"));
        }
        Ok(out)
    }

    fn advance_lineage(&self, records: &[(u64, Vec<u8>)]) -> Result<OrgLineage> {
        let decoded = records
            .iter()
            .map(|(g, b)| {
                let rec = SignedOrgRecord::decode(b)?;
                if rec.generation() != *g {
                    return Err(bad("org lineage list"));
                }
                Ok(rec)
            })
            .collect::<Result<Vec<_>>>()?;
        if !decoded
            .windows(2)
            .all(|w| w[0].generation() < w[1].generation())
        {
            return Err(bad("org lineage list"));
        }
        let (first, rest) = decoded
            .split_first()
            .ok_or(IntegrityError::OrgLineageRollback)?;
        if let Some(f) = genesis_fingerprint(first)
            && f != self.fingerprint()
        {
            return Err(mismatch());
        }
        if first.org_id() != self.lineage.org_id {
            return Err(IntegrityError::WrongContext.into());
        }
        let head = self.head();
        if first.generation() != head.generation {
            return Err(IntegrityError::OrgLineageRollback.into());
        }
        if first.hash() != head.hash {
            return Err(fork_or_bad_signature(first, &self.lineage.identity_pub));
        }
        let mut lineage = self.lineage.clone();
        for rec in rest {
            if let Some(f) = genesis_fingerprint(rec)
                && f != self.fingerprint()
            {
                return Err(mismatch());
            }
            if rec.generation() <= lineage.head().generation {
                // `apply` takes the current head again as a no-op; here
                // every record must move it forward.
                lineage.apply(rec)?;
                return Err(IntegrityError::OrgLineageRollback.into());
            }
            lineage = lineage.apply(rec)?;
        }
        Ok(lineage)
    }

    fn advance_roster(
        &self,
        lineage: &OrgLineage,
        rosters: &[(u64, Vec<u8>)],
    ) -> Result<Option<RosterBody>> {
        if let Some(pinned) = &self.roster {
            check_checkpoints(lineage, pinned)?;
        }
        if rosters.is_empty() {
            return Ok(self.roster.clone());
        }
        let decoded = rosters
            .iter()
            .map(|(s, b)| {
                let rec = SignedRoster::decode(b)?;
                if rec.body.seq != *s {
                    return Err(bad("org roster list"));
                }
                Ok(rec)
            })
            .collect::<Result<Vec<_>>>()?;
        if !decoded.windows(2).all(|w| w[0].body.seq < w[1].body.seq) {
            return Err(bad("org roster list"));
        }
        let Some(pinned) = &self.roster else {
            return accept_first_roster(lineage, &decoded).map(Some);
        };
        // The leading entries at or below the pinned seq: checked against
        // the pinned chain, then dropped.
        let split = decoded
            .iter()
            .position(|r| r.body.seq > pinned.seq)
            .unwrap_or(decoded.len());
        let (old, new) = decoded.split_at(split);
        let mut expected: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
        expected.insert(pinned.seq, pinned.hash());
        if pinned.seq > 1 {
            expected.insert(pinned.seq - 1, pinned.prev_hash);
        }
        let mut old: Vec<&SignedRoster> = old.iter().collect();
        old.sort_by_key(|r| std::cmp::Reverse(r.body.seq));
        for r in old {
            let s = r.body.seq;
            let Some(want) = expected.get(&s) else {
                continue;
            };
            if r.body.hash() != *want {
                return Err(IntegrityError::OrgRosterFork.into());
            }
            if s > 1 {
                expected.insert(s - 1, r.body.prev_hash);
            }
        }
        let top = decoded.iter().map(|r| r.body.seq).max().unwrap_or(0);
        if top < pinned.seq {
            return Err(IntegrityError::OrgRosterRollback.into());
        }
        accept_after(lineage, pinned, new).map(Some)
    }

    /// The admin read out `fpr_from_admin` (TOFU confirmation): the pinned
    /// fingerprint or `OrgPinMismatch`. Only a TOFU pin is confirmed
    /// (`Validation` otherwise); confirming twice changes nothing.
    pub fn confirm_tofu(&self, fpr_from_admin: &[u8; 32]) -> Result<OrgPin> {
        if !matches!(self.source, PinSource::Tofu { .. }) {
            return Err(misuse("source", "only a TOFU pin is confirmed"));
        }
        if *fpr_from_admin != self.fingerprint() {
            return Err(mismatch());
        }
        Ok(OrgPin {
            source: PinSource::Tofu { verified: true },
            ..self.clone()
        })
    }

    fn body_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(&(&self.source, &self.lineage, &self.roster))
            .expect("org pin encodes")
    }

    fn encoded_len(&self) -> usize {
        1 + self.body_bytes().len()
    }

    /// `[ORG_PIN_VERSION] || postcard((source, lineage, roster))`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![ORG_PIN_VERSION];
        out.extend(self.body_bytes());
        out
    }

    /// Strict: the version byte (`InvalidFormat("org pin version")`), the
    /// size cap, the whole buffer, canonical re-encoding, then the shape of
    /// the whole state (`check_state`).
    pub fn decode(b: &[u8]) -> Result<OrgPin> {
        let (version, body) = b.split_first().ok_or(bad("org pin"))?;
        if *version != ORG_PIN_VERSION {
            return Err(bad("org pin version"));
        }
        if b.len() > MAX_ORG_PIN_BYTES {
            return Err(bad("org pin size"));
        }
        let (source, lineage, roster): (PinSource, OrgLineage, Option<RosterBody>) =
            decode_strict_with(body, bad("org pin"))?;
        let pin = OrgPin {
            source,
            lineage,
            roster,
        };
        pin.check_state()?;
        Ok(pin)
    }

    /// What a pin built by `pin_org` and `advance` always holds: a
    /// lineage with generations `0..n` in order, sound owners per head, a
    /// sound name, keys and fingerprint; a roster (if any) of sound shape,
    /// of this org, under a known head. Any failure is `InvalidFormat`.
    fn check_state(&self) -> Result<()> {
        let fail = |_| bad("org pin state");
        let l = &self.lineage;
        if l.heads.is_empty() {
            return Err(bad("org pin state"));
        }
        for (i, h) in l.heads.iter().enumerate() {
            if h.generation != i as u64 || (i == 0 && h.roster_checkpoint.is_some()) {
                return Err(bad("org pin state"));
            }
            check_owners(&h.owners).map_err(fail)?;
            if let Some(c) = &h.roster_checkpoint {
                c.check().map_err(fail)?;
            }
        }
        if l.fingerprint == [0; 32] {
            return Err(bad("org pin state"));
        }
        check_name(&l.name).map_err(fail)?;
        check_identity_pub(&l.identity_pub, "org identity key").map_err(fail)?;
        check_kem(&l.audit_kem_pub, "org audit kem key").map_err(fail)?;
        if let Some(r) = &self.roster {
            r.check().map_err(fail)?;
            if r.org_id != l.org_id || l.find(&r.org_head).is_none() {
                return Err(bad("org pin state"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_is_52_uppercase() {
        let s = fingerprint_base32(&[0xFF; 32]);
        assert_eq!(s.len(), FPR_BASE32_CHARS);
        assert_eq!(s, s.to_ascii_uppercase());
    }

    #[test]
    fn op1_detection() {
        assert!(is_op1("v=op1; org=x"));
        assert!(is_op1(" v = op1 "));
        assert!(!is_op1("v=op2; org=x"));
        assert!(!is_op1("v=spf1 -all"));
        assert!(!is_op1(""));
    }
}
