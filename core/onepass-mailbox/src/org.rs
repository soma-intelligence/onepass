//! Record kinds of an organization mailbox (plan `org`).

/// The org lineage record: write-once on the server.
pub const ORG_LINEAGE_KIND: u8 = 29;
/// The org roster record: write-once on the server.
pub const ORG_ROSTER_KIND: u8 = 30;
/// The org key set record: mutable.
pub const ORG_KEYSET_KIND: u8 = 31;
/// The org join record: mutable.
pub const ORG_JOIN_KIND: u8 = 32;

/// Kinds the server accepts one put of per key and never deletes (29, 30).
pub fn is_immutable_kind(kind: u8) -> bool {
    kind == ORG_LINEAGE_KIND || kind == ORG_ROSTER_KIND
}
