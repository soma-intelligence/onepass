//! The constants and batch shaping of the round, ported from
//! `SyncCoordinator.swift` with the same values and the same order.

use std::collections::BTreeMap;
use std::time::Duration;

use onepass_core::Id;
use onepass_core::store::RecordKind;

use crate::transport::Outgoing;

/// Turns of a round (fetch, rebase, send) before it ends unsettled.
pub const MAX_TURNS: u32 = 3;
/// Zone resets a round handles before it ends unsettled.
pub const MAX_RESETS: u32 = 2;
/// Rounds in a row that met an unreadable record before the status says so.
pub const UNREADABLE_ROUNDS_BEFORE_REPORT: u32 = 5;
/// Rounds in a row that withdrew an epoch and rerun at once; past this, the
/// next round waits for the retry delays.
pub const MAX_QUICK_CONFLICT_ROUNDS: u32 = 3;
/// Backoff of a round that could not reach or settle with the server.
pub const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
];
/// Rotation phases pushed in one round at most.
pub const MAX_PHASES_PER_ROUND: u32 = 3;

/// Store meta key of the mailbox change cursor. Never CloudKit's.
pub const CURSOR_KEY: &str = "mailbox.cursor";
/// Store meta key of the mailbox incarnation the store is bound to.
pub const INCARNATION_KEY: &str = "mailbox.incarnation";

/// Pending order regrouped per vault: records outside vaults (account,
/// keysets, vault keys and metas), then attachment chunks (before the items
/// that list them), then for each vault with a pending manifest its items
/// followed by its manifest, then items without a pending manifest, then
/// the other kinds (lists, deliveries, sync home), then lineage records,
/// then deletions in core order (after every manifest).
pub fn ordered(outgoing: Vec<Outgoing>) -> Vec<Outgoing> {
    let (writes, deletions): (Vec<Outgoing>, Vec<Outgoing>) =
        outgoing.into_iter().partition(|o| o.change.data.is_some());
    let code = |o: &Outgoing| o.change.kind.code();
    let item = RecordKind::Item.code();
    let manifest = RecordKind::Manifest.code();
    let attachment = RecordKind::Attachment.code();
    let mut result: Vec<Outgoing> = writes.iter().filter(|o| code(o) < item).cloned().collect();
    result.extend(writes.iter().filter(|o| code(o) == attachment).cloned());
    let mut items: BTreeMap<Option<Id>, Vec<Outgoing>> = BTreeMap::new();
    let mut item_order: Vec<Option<Id>> = Vec::new();
    for o in writes.iter().filter(|o| code(o) == item) {
        let vault = o
            .change
            .data
            .as_deref()
            .and_then(|d| d.get(..16))
            .map(|p| Id(p.try_into().expect("16 bytes")));
        if !items.contains_key(&vault) {
            item_order.push(vault);
        }
        items.entry(vault).or_default().push(o.clone());
    }
    for m in writes.iter().filter(|o| code(o) == manifest) {
        result.extend(items.remove(&Some(m.change.id)).unwrap_or_default());
        result.push(m.clone());
    }
    for vault in item_order {
        result.extend(items.remove(&vault).unwrap_or_default());
    }
    let lineage = RecordKind::Lineage.code();
    result.extend(
        writes
            .iter()
            .filter(|o| code(o) > manifest && code(o) != attachment && code(o) != lineage)
            .cloned(),
    );
    // A lineage record goes last: a rotation's phase 1 lands before the
    // record that announces it (rotation spec 7.1).
    result.extend(writes.into_iter().filter(|o| code(o) == lineage));
    result.extend(deletions);
    result
}

/// Consecutive slices within the limits (a single oversized change goes
/// alone).
pub fn split(outgoing: Vec<Outgoing>, max_records: usize, max_bytes: usize) -> Vec<Vec<Outgoing>> {
    let mut batches = Vec::new();
    let mut current: Vec<Outgoing> = Vec::new();
    let mut bytes = 0usize;
    for o in outgoing {
        let size = o.batch_bytes();
        if !current.is_empty()
            && (current.len() >= max_records.max(1) || bytes.saturating_add(size) > max_bytes)
        {
            batches.push(std::mem::take(&mut current));
            bytes = 0;
        }
        bytes = bytes.saturating_add(size);
        current.push(o);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// The delay of the `attempt`-th retry in a row (0 first).
pub fn retry_delay(attempt: u32) -> Duration {
    RETRY_DELAYS[(attempt as usize).min(RETRY_DELAYS.len() - 1)]
}

#[cfg(test)]
mod tests {
    use onepass_core::sync::Change;

    use super::*;

    fn out(kind: RecordKind, id: Id, data: Option<Vec<u8>>) -> Outgoing {
        Outgoing {
            change: Change {
                kind,
                id,
                version: 1,
                data,
            },
            server_meta: None,
        }
    }

    #[test]
    fn items_go_before_their_manifest() {
        let v = Id([1; 16]);
        let w = Id([2; 16]);
        let item = |vault: Id| {
            let mut d = vault.0.to_vec();
            d.push(0);
            out(RecordKind::Item, Id::new(), Some(d))
        };
        let list = vec![
            out(RecordKind::Manifest, v, Some(vec![1])),
            item(v),
            out(RecordKind::Item, Id::new(), None),
            item(w),
            out(RecordKind::DeviceList, Id::new(), Some(vec![1])),
            out(RecordKind::Lineage, Id::new(), Some(vec![1])),
            out(RecordKind::VaultKey, v, Some(vec![1])),
            item(v),
            out(RecordKind::KeyDelivery, Id::new(), Some(vec![1])),
        ];
        let kinds: Vec<(u8, bool)> = ordered(list)
            .iter()
            .map(|o| (o.change.kind.code(), o.change.data.is_some()))
            .collect();
        assert_eq!(
            kinds,
            [
                (3, true),
                (5, true),
                (5, true),
                (6, true),
                (5, true),
                (8, true),
                (12, true),
                (10, true),
                (5, false)
            ]
        );
    }

    #[test]
    fn split_respects_both_limits() {
        let list: Vec<Outgoing> = (0..7)
            .map(|_| out(RecordKind::Item, Id::new(), Some(vec![0; 100])))
            .collect();
        let sizes: Vec<usize> = split(list.clone(), 3, usize::MAX)
            .iter()
            .map(Vec::len)
            .collect();
        assert_eq!(sizes, [3, 3, 1]);
        let sizes: Vec<usize> = split(list, 100, 400).iter().map(Vec::len).collect();
        assert_eq!(sizes, [2, 2, 2, 1]);
        // One oversized change goes alone.
        let big = vec![out(RecordKind::Item, Id::new(), Some(vec![0; 1000]))];
        assert_eq!(split(big, 3, 10).len(), 1);
    }
}
