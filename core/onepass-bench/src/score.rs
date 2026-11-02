//! Detection and fill scoring of one site, macro F1 over a run, regressions
//! against pinned verdicts. Inputs are roles and booleans, never a value.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::sites::{Kind, Site};

/// What the probe saw for one truth field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    pub selector: String,
    pub found: bool,
    /// Extension `FieldRole` of the field, `None` when no detected form holds it.
    pub detected: Option<String>,
    /// The field holds a value after the fill.
    pub filled: bool,
    /// The value is the fake value the bench meant for the field's truth role.
    pub expected_value: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    SkippedRobots,
    LoadError,
    TruthStale,
    ProbeError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldScore {
    pub selector: String,
    pub truth: String,
    /// Detected role as a truth label (`none` when not detected).
    pub detected: String,
    pub correct: bool,
    pub filled: bool,
    pub expected_value: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSummary {
    pub intent: String,
    pub action: String,
    pub groups: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteScore {
    pub id: String,
    pub kind: Kind,
    pub status: Status,
    pub fields: Vec<FieldScore>,
    pub detection_pass: bool,
    pub plan: Option<PlanSummary>,
    pub fill_pass: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Extension `FieldRole` to truth label.
pub fn label_of(role: &str) -> &str {
    match role {
        "current_password" => "password",
        "confirm_password" => "new_password",
        "bday" => "birth_date",
        "unknown" | "remember_me" => "none",
        r if crate::sites::ROLES.contains(&r) => r,
        _ => "none",
    }
}

/// Password and new password are one family (lab ruling R23).
pub fn family(label: &str) -> &str {
    match label {
        "new_password" => "password",
        l => l,
    }
}

/// Truth families a fill of this kind must write.
fn must_fill(kind: Kind, fam: &str) -> bool {
    match kind {
        Kind::Login => matches!(fam, "username" | "email" | "password"),
        Kind::Signup => fam == "password",
    }
}

pub fn score_site(site: &Site, observed: &[Observed], plan: Option<PlanSummary>) -> SiteScore {
    let mut fields = Vec::with_capacity(site.fields.len());
    let mut stale = false;
    let mut fill_ok = plan.as_ref().is_some_and(|p| p.groups > 0);
    for t in &site.fields {
        let o = observed.iter().find(|o| o.selector == t.selector);
        let Some(o) = o.filter(|o| o.found) else {
            stale = true;
            continue;
        };
        let detected = o.detected.as_deref().map(label_of).unwrap_or("none");
        let correct = std::iter::once(&t.role)
            .chain(t.accept.iter())
            .any(|r| family(r) == family(detected));
        let fam = family(&t.role);
        if fam == "none" {
            fill_ok &= !o.filled;
        } else if must_fill(site.kind, fam) {
            fill_ok &= o.filled && o.expected_value;
        }
        fields.push(FieldScore {
            selector: t.selector.clone(),
            truth: t.role.clone(),
            detected: detected.to_string(),
            correct,
            filled: o.filled,
            expected_value: o.expected_value,
        });
    }
    if stale {
        return SiteScore {
            fields,
            plan,
            ..unscored(site, Status::TruthStale, None)
        };
    }
    SiteScore {
        id: site.id.clone(),
        kind: site.kind,
        status: Status::Ok,
        detection_pass: fields.iter().all(|f| f.correct),
        fields,
        plan,
        fill_pass: fill_ok,
        error: None,
    }
}

/// Site with no measurement (skipped, load or probe error).
pub fn unscored(site: &Site, status: Status, error: Option<String>) -> SiteScore {
    SiteScore {
        id: site.id.clone(),
        kind: site.kind,
        status,
        fields: Vec::new(),
        detection_pass: false,
        plan: None,
        fill_pass: false,
        error,
    }
}

/// Macro F1 over families of truth and detected labels, on the fields of `Ok` sites.
pub fn merged_macro_f1(sites: &[SiteScore]) -> Option<f64> {
    let pairs: Vec<(&str, &str)> = sites
        .iter()
        .filter(|s| s.status == Status::Ok)
        .flat_map(|s| s.fields.iter())
        .map(|f| (family(&f.truth), family(&f.detected)))
        .collect();
    if pairs.is_empty() {
        return None;
    }
    let classes: BTreeSet<&str> = pairs.iter().flat_map(|(t, p)| [*t, *p]).collect();
    let mut sum = 0.0;
    for c in &classes {
        let tp = pairs.iter().filter(|(t, p)| t == c && p == c).count() as f64;
        let fp = pairs.iter().filter(|(t, p)| t != c && p == c).count() as f64;
        let fn_ = pairs.iter().filter(|(t, p)| t == c && p != c).count() as f64;
        sum += 2.0 * tp / (2.0 * tp + fp + fn_);
    }
    Some(sum / classes.len() as f64)
}

/// Pinned verdict of a site in offline mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub detection_pass: bool,
    pub fill_pass: bool,
}

pub fn verdicts(sites: &[SiteScore]) -> BTreeMap<String, Verdict> {
    sites
        .iter()
        .map(|s| {
            (
                s.id.clone(),
                Verdict {
                    detection_pass: s.detection_pass,
                    fill_pass: s.fill_pass,
                },
            )
        })
        .collect()
}

/// Ids whose pinned pass turned into a fail (or that vanished).
pub fn regressions(
    expected: &BTreeMap<String, Verdict>,
    actual: &BTreeMap<String, Verdict>,
) -> Vec<String> {
    expected
        .iter()
        .filter(|(id, e)| match actual.get(*id) {
            None => e.detection_pass || e.fill_pass,
            Some(a) => (e.detection_pass && !a.detection_pass) || (e.fill_pass && !a.fill_pass),
        })
        .map(|(id, _)| id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sites::{Site, TruthField};

    fn tf(sel: &str, role: &str, accept: &[&str]) -> TruthField {
        TruthField {
            selector: sel.into(),
            role: role.into(),
            accept: accept.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn site(kind: Kind, fields: Vec<TruthField>) -> Site {
        Site {
            id: "s".into(),
            url: "https://s.example/login".into(),
            kind,
            lang: "en".into(),
            fields,
        }
    }

    fn obs(sel: &str, det: Option<&str>, filled: bool, expected: bool) -> Observed {
        Observed {
            selector: sel.into(),
            found: true,
            detected: det.map(Into::into),
            filled,
            expected_value: expected,
        }
    }

    fn plan(groups: usize) -> Option<PlanSummary> {
        Some(PlanSummary {
            intent: "login".into(),
            action: "fill".into(),
            groups,
        })
    }

    #[test]
    fn roles_map_to_labels_and_families() {
        assert_eq!(label_of("current_password"), "password");
        assert_eq!(label_of("confirm_password"), "new_password");
        assert_eq!(label_of("bday"), "birth_date");
        assert_eq!(label_of("unknown"), "none");
        assert_eq!(label_of("remember_me"), "none");
        assert_eq!(label_of("email"), "email");
        assert_eq!(family("new_password"), "password");
        assert_eq!(family("email"), "email");
    }

    #[test]
    fn login_detected_and_filled_passes() {
        let s = site(
            Kind::Login,
            vec![tf("#u", "username", &["email"]), tf("#p", "password", &[])],
        );
        let o = [
            obs("#u", Some("email"), true, true),
            obs("#p", Some("current_password"), true, true),
        ];
        let r = score_site(&s, &o, plan(1));
        assert_eq!(r.status, Status::Ok);
        assert!(r.detection_pass && r.fill_pass);
        assert!(r.fields.iter().all(|f| f.correct));
    }

    #[test]
    fn signup_new_password_counts_as_password_family() {
        let s = site(Kind::Signup, vec![tf("#p", "new_password", &[])]);
        let r = score_site(
            &s,
            &[obs("#p", Some("current_password"), true, true)],
            plan(1),
        );
        assert!(r.detection_pass && r.fill_pass);
    }

    #[test]
    fn wrong_role_or_wrong_value_fails() {
        let s = site(
            Kind::Login,
            vec![tf("#u", "username", &[]), tf("#p", "password", &[])],
        );
        let r = score_site(
            &s,
            &[
                obs("#u", Some("email"), true, true),
                obs("#p", Some("current_password"), true, true),
            ],
            plan(1),
        );
        assert!(!r.detection_pass);
        assert!(r.fill_pass);
        let r = score_site(
            &s,
            &[
                obs("#u", Some("username"), true, false),
                obs("#p", Some("current_password"), true, true),
            ],
            plan(1),
        );
        assert!(r.detection_pass && !r.fill_pass);
        let r = score_site(
            &s,
            &[
                obs("#u", Some("username"), true, true),
                obs("#p", Some("current_password"), true, true),
            ],
            plan(0),
        );
        assert!(!r.fill_pass);
    }

    #[test]
    fn none_field_filled_fails_the_fill() {
        let s = site(
            Kind::Login,
            vec![
                tf("#u", "username", &[]),
                tf("#p", "password", &[]),
                tf("#trap", "none", &[]),
            ],
        );
        let ok = [
            obs("#u", Some("username"), true, true),
            obs("#p", Some("current_password"), true, true),
        ];
        let mut o = ok.to_vec();
        o.push(obs("#trap", None, true, false));
        let r = score_site(&s, &o, plan(1));
        assert!(!r.fill_pass);
        assert!(r.detection_pass, "undetected none field is correct");
        let mut o = ok.to_vec();
        o.push(obs("#trap", Some("unknown"), false, false));
        assert!(score_site(&s, &o, plan(1)).fill_pass);
    }

    #[test]
    fn missing_selector_is_truth_stale() {
        let s = site(Kind::Login, vec![tf("#u", "username", &[])]);
        let mut o = obs("#u", None, false, false);
        o.found = false;
        let r = score_site(&s, &[o], plan(0));
        assert_eq!(r.status, Status::TruthStale);
        assert!(!r.detection_pass && !r.fill_pass);
    }

    #[test]
    fn macro_f1_over_ok_sites() {
        let s = site(
            Kind::Login,
            vec![tf("#u", "username", &[]), tf("#p", "password", &[])],
        );
        let good = score_site(
            &s,
            &[
                obs("#u", Some("username"), true, true),
                obs("#p", Some("new_password"), true, true),
            ],
            plan(1),
        );
        assert_eq!(merged_macro_f1(std::slice::from_ref(&good)), Some(1.0));
        let bad = score_site(
            &s,
            &[
                obs("#u", Some("email"), true, true),
                obs("#p", Some("current_password"), true, true),
            ],
            plan(1),
        );
        // username: tp 0 fn 1; email: fp 1; password: 1. F1 = (0 + 0 + 1) / 3.
        let f = merged_macro_f1(&[bad]).unwrap();
        assert!((f - 1.0 / 3.0).abs() < 1e-9, "{f}");
        assert_eq!(merged_macro_f1(&[]), None);
    }

    #[test]
    fn regressions_are_pinned_passes_that_fail() {
        let v = |d, f| Verdict {
            detection_pass: d,
            fill_pass: f,
        };
        let expected: BTreeMap<_, _> = [
            ("a".to_string(), v(true, true)),
            ("b".to_string(), v(false, false)),
            ("c".to_string(), v(true, false)),
            ("gone".to_string(), v(true, true)),
        ]
        .into();
        let actual: BTreeMap<_, _> = [
            ("a".to_string(), v(true, false)),
            ("b".to_string(), v(true, true)),
            ("c".to_string(), v(true, false)),
        ]
        .into();
        assert_eq!(regressions(&expected, &actual), vec!["a", "gone"]);
    }
}
