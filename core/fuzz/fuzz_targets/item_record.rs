#![no_main]

//! An item record as a hostile store serves it: `vault prefix || ItemRecord`
//! split and decoded, then hashed and matched against a manifest, as
//! `Repository` does before any key is used.

use libfuzzer_sys::fuzz_target;
use onepass_core::Id;
use onepass_core::manifest::{Manifest, ManifestEntry, check_records, record_hash};
use onepass_core::repo::split_item_record;
use onepass_core::vault::ItemRecord;

fuzz_target!(|data: &[u8]| {
    let Ok((vault, body)) = split_item_record(data) else {
        return;
    };
    let Ok(rec) = ItemRecord::decode(body) else {
        return;
    };
    let empty = Manifest::next(None, vault, vec![]).unwrap();
    let _ = check_records(&empty, std::slice::from_ref(&rec));
    // A manifest that lists this very record: the matching path.
    let entry = ManifestEntry {
        item_id: rec.item_id,
        version: rec.version,
        record_hash: record_hash(&rec),
    };
    if let Ok(m) = Manifest::next(None, Id([0; 16]), vec![entry]) {
        let _ = check_records(&m, std::slice::from_ref(&rec));
    }
});
