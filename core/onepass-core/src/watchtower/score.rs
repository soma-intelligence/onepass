//! Health scores (spec 3.5).

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::id::Id;
use crate::model::Item;

use super::checks::{Finding, ser_id};

/// Score of one vault over its analyzed items.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VaultScore {
    #[serde(serialize_with = "ser_id")]
    pub vault_id: Id,
    pub score: u8,
    pub items: u32,
}

/// Global score and per-vault scores of the analyzed items.
///
/// Item health is `max(0, 1 - sum of weights)`; a score is
/// `round(100 * mean health)`, half up, 100 with no item. The global score
/// averages all items, not the vault scores. Everything is computed in
/// integer hundredths so that ties round exactly.
pub(crate) fn scores(items: &[&Item], findings: &[Finding]) -> (u8, Vec<VaultScore>) {
    let mut penalty: HashMap<Id, u32> = HashMap::new();
    for f in findings {
        let p = penalty.entry(f.item_id).or_insert(0);
        *p = p.saturating_add(f.severity.weight_hundredths());
    }
    // Health of an item in hundredths, 0 to 100.
    let health = |item: &Item| 100u32.saturating_sub(penalty.get(&item.id).copied().unwrap_or(0));
    // Per vault: sum of health and item count.
    let mut by_vault: BTreeMap<Id, (u64, u64)> = BTreeMap::new();
    let mut total: (u64, u64) = (0, 0);
    for item in items {
        let h = u64::from(health(item));
        total.0 = total.0.saturating_add(h);
        total.1 = total.1.saturating_add(1);
        let entry = by_vault.entry(item.vault_id).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(h);
        entry.1 = entry.1.saturating_add(1);
    }
    let vaults = by_vault
        .into_iter()
        .map(|(vault_id, (sum, n))| VaultScore {
            vault_id,
            score: to_score(sum, n),
            items: u32::try_from(n).unwrap_or(u32::MAX),
        })
        .collect();
    (to_score(total.0, total.1), vaults)
}

/// `round(sum / n)` half up, where `sum` adds healths in hundredths (each
/// at most 100); 100 when `n` is zero.
fn to_score(sum: u64, n: u64) -> u8 {
    if n == 0 {
        return 100;
    }
    // (2 * sum + n) / (2 * n) is floor(sum / n + 1/2). Item counts are far
    // below 2^56, so the products do not overflow; saturate anyway.
    let rounded = sum
        .saturating_mul(2)
        .saturating_add(n)
        .checked_div(n.saturating_mul(2))
        .unwrap_or(100);
    u8::try_from(rounded.min(100)).unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ItemType, new_item};
    use crate::watchtower::{Check, Detail, Severity};

    fn finding(item: &Item, check: Check) -> Finding {
        Finding {
            item_id: item.id,
            vault_id: item.vault_id,
            check,
            severity: check.severity(),
            field_id: None,
            detail: Detail::None,
        }
    }

    #[test]
    fn score_formula() {
        let v1 = Id([1; 16]);
        let v2 = Id([2; 16]);
        let healthy = new_item(ItemType::Login, v1, "a");
        let high = new_item(ItemType::Login, v1, "b");
        let worst = new_item(ItemType::Login, v2, "c");
        assert_eq!(Check::Weak.severity(), Severity::High);
        assert_eq!(Check::Compromised.severity(), Severity::Critical);
        let findings = [
            finding(&high, Check::Weak),
            finding(&worst, Check::Compromised),
            finding(&worst, Check::Reused),
            // Info weighs nothing.
            finding(&healthy, Check::Duplicate),
        ];
        let (global, vaults) = scores(&[&healthy, &high, &worst], &findings);
        // round(100 * (1 + 0.5 + 0) / 3)
        assert_eq!(global, 50);
        assert_eq!(
            vaults,
            [
                VaultScore {
                    vault_id: v1,
                    score: 75,
                    items: 2
                },
                VaultScore {
                    vault_id: v2,
                    score: 0,
                    items: 1
                },
            ]
        );
    }

    #[test]
    fn rounds_to_nearest() {
        let v = Id([1; 16]);
        let a = new_item(ItemType::Login, v, "a");
        let b = new_item(ItemType::Login, v, "b");
        let c = new_item(ItemType::Login, v, "c");
        // (0.9 + 1 + 1) / 3 = 0.9666... -> 97
        let (global, _) = scores(&[&a, &b, &c], &[finding(&a, Check::OldPassword)]);
        assert_eq!(global, 97);
    }

    #[test]
    fn exact_half_rounds_up() {
        // Healthy + (High + Medium + Low): (100 + 15) / 2 = 57.5 -> 58.
        // Summing f64 weights gives 57.4999... and rounds to 57.
        let v = Id([1; 16]);
        let a = new_item(ItemType::Login, v, "a");
        let b = new_item(ItemType::Login, v, "b");
        let findings = [
            finding(&b, Check::Weak),
            finding(&b, Check::InsecureUrl),
            finding(&b, Check::OldPassword),
        ];
        let (global, vaults) = scores(&[&a, &b], &findings);
        assert_eq!(global, 58);
        assert_eq!(vaults[0].score, 58);
    }

    #[test]
    fn empty_vault_scores_100() {
        let (global, vaults) = scores(&[], &[]);
        assert_eq!(global, 100);
        assert!(vaults.is_empty());
    }
}
