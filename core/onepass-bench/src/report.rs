//! JSON report of a run (spec 5.2). Holds roles, selectors and verdicts only.

use serde::{Deserialize, Serialize};

use crate::score::{SiteScore, Status, merged_macro_f1};

pub const REPORT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub sites: usize,
    pub scored: usize,
    pub skipped: usize,
    pub stale: usize,
    pub errors: usize,
    pub fields: usize,
    pub fields_correct: usize,
    pub detection_accuracy: Option<f64>,
    pub merged_macro_f1: Option<f64>,
    pub detection_pass: usize,
    pub fill_pass: usize,
    pub fill_rate: Option<f64>,
}

impl Summary {
    pub fn of(sites: &[SiteScore]) -> Summary {
        let ok: Vec<&SiteScore> = sites.iter().filter(|s| s.status == Status::Ok).collect();
        let fields: usize = ok.iter().map(|s| s.fields.len()).sum();
        let correct: usize = ok
            .iter()
            .map(|s| s.fields.iter().filter(|f| f.correct).count())
            .sum();
        let fill_pass = ok.iter().filter(|s| s.fill_pass).count();
        let ratio = |n: usize, d: usize| (d > 0).then(|| n as f64 / d as f64);
        Summary {
            sites: sites.len(),
            scored: ok.len(),
            skipped: sites
                .iter()
                .filter(|s| s.status == Status::SkippedRobots)
                .count(),
            stale: sites
                .iter()
                .filter(|s| s.status == Status::TruthStale)
                .count(),
            errors: sites
                .iter()
                .filter(|s| matches!(s.status, Status::LoadError | Status::ProbeError))
                .count(),
            fields,
            fields_correct: correct,
            detection_accuracy: ratio(correct, fields),
            merged_macro_f1: merged_macro_f1(sites),
            detection_pass: ok.iter().filter(|s| s.detection_pass).count(),
            fill_pass,
            fill_rate: ratio(fill_pass, ok.len()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub version: u32,
    pub mode: String,
    /// Unix seconds at the start of the run.
    pub started: u64,
    pub chrome: String,
    pub probe_sha256: String,
    pub summary: Summary,
    pub sites: Vec<SiteScore>,
}

impl Report {
    pub fn new(
        mode: &str,
        started: u64,
        chrome: &str,
        probe_sha256: &str,
        sites: Vec<SiteScore>,
    ) -> Report {
        Report {
            version: REPORT_VERSION,
            mode: mode.to_string(),
            started,
            chrome: chrome.to_string(),
            probe_sha256: probe_sha256.to_string(),
            summary: Summary::of(&sites),
            sites,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::{FieldScore, PlanSummary, Status};
    use crate::sites::Kind;

    fn site(id: &str, status: Status, correct: bool, fill: bool) -> SiteScore {
        SiteScore {
            id: id.into(),
            kind: Kind::Login,
            status,
            fields: if status == Status::Ok {
                vec![FieldScore {
                    selector: "#p".into(),
                    truth: "password".into(),
                    detected: if correct { "password" } else { "none" }.into(),
                    correct,
                    filled: fill,
                    expected_value: fill,
                }]
            } else {
                vec![]
            },
            detection_pass: correct,
            plan: Some(PlanSummary {
                intent: "login".into(),
                action: "fill".into(),
                groups: 1,
            }),
            fill_pass: fill,
            error: None,
        }
    }

    #[test]
    fn summary_counts() {
        let s = Summary::of(&[
            site("a", Status::Ok, true, true),
            site("b", Status::Ok, false, false),
            site("c", Status::SkippedRobots, false, false),
            site("d", Status::TruthStale, false, false),
            site("e", Status::LoadError, false, false),
        ]);
        assert_eq!(
            (s.sites, s.scored, s.skipped, s.stale, s.errors),
            (5, 2, 1, 1, 1)
        );
        assert_eq!((s.fields, s.fields_correct, s.fill_pass), (2, 1, 1));
        assert_eq!(s.detection_accuracy, Some(0.5));
        assert_eq!(s.fill_rate, Some(0.5));
    }

    #[test]
    fn report_round_trips_and_has_no_value_slot() {
        let r = Report::new(
            "offline",
            1,
            "Chromium 1",
            "ab",
            vec![site("a", Status::Ok, true, true)],
        );
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Report>(&json).unwrap(), r);
        assert!(!json.contains("\"value\""));
        assert!(json.contains("\"status\":\"ok\""));
    }
}
