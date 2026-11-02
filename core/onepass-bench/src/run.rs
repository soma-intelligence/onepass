//! One run of the bench: for each site, robots.txt (live), load, probe, plan, fill, read back,
//! score, and the labelled rows for `ml/`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::cdp::{Cdp, CdpError, Source};
use crate::planner::{Planned, plan_for};
use crate::report::Report;
use crate::robots::{AGENT, Robots};
use crate::score::{Observed, SiteScore, Status, family, label_of, score_site, unscored};
use crate::sites::{Kind, Site, SiteList};

/// Fake values (spec section 2). None is a real secret; none leaves the page.
pub const FAKE_USERNAME: &str = "bench.user";
pub const FAKE_EMAIL: &str = "bench.user@example.invalid";
pub const FAKE_PASSWORD: &str = "Bench-Fake-Pass-1!";
pub const FAKE_NEW_PASSWORD: &str = "Bench-Fake-New-Pass-2!";
/// Seed name of the bench rows (ml/onepass_ml/bench.py splits on it).
pub const ROWS_SEED: &str = "bench-2026-11-02";

const CALL: Duration = Duration::from_secs(30);
const LOAD: Duration = Duration::from_secs(15);
const QUIET: Duration = Duration::from_millis(2500);
const WORLD: &str = "onepass-bench";

/// Main-world guard installed before any page script (mirror of `installGuard` in the probe).
pub const MAIN_WORLD_GUARD: &str = r#"(() => {
  const p = HTMLFormElement.prototype;
  p.submit = function submit() {};
  p.requestSubmit = function requestSubmit() {};
  addEventListener("submit", (e) => { e.preventDefault(); e.stopImmediatePropagation(); }, true);
})();"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Live,
    Offline,
}

pub struct RunConfig {
    pub mode: Mode,
    pub sites: SiteList,
    pub recordings: PathBuf,
    pub only: Option<String>,
    pub record: bool,
    pub delay: Duration,
    pub probe_js: String,
}

/// Values the filler gets for a group of the plan.
pub fn values_for(generated: bool) -> Value {
    if generated {
        json!({"new_password": FAKE_NEW_PASSWORD, "confirm_password": FAKE_NEW_PASSWORD})
    } else {
        json!({"username": FAKE_USERNAME, "email": FAKE_EMAIL, "current_password": FAKE_PASSWORD})
    }
}

/// The values a truth field may hold after a correct fill (empty: it must stay empty, or it is
/// not checked).
pub fn expected_values(kind: Kind, truth_role: &str) -> Vec<&'static str> {
    match (family(truth_role), kind) {
        ("username" | "email", Kind::Login) => vec![FAKE_USERNAME, FAKE_EMAIL],
        ("password", Kind::Login) => vec![FAKE_PASSWORD],
        ("password", Kind::Signup) => vec![FAKE_NEW_PASSWORD],
        _ => vec![],
    }
}

/// Model labels a bench row may carry as its target (truth roles outside the label set give no row).
const ROW_TARGETS: &[&str] = &[
    "username",
    "email",
    "password",
    "new_password",
    "otp",
    "cc_name",
    "cc_number",
    "cc_exp",
    "cc_exp_month",
    "cc_exp_year",
    "cc_csc",
    "given_name",
    "family_name",
    "tel",
    "birth_date",
    "organization",
    "address_line1",
    "address_line2",
    "postal_code",
    "city",
    "country",
    "none",
];

/// One labelled row per truth field the extractor reached (DatasetRow of the lab plus
/// `heuristic`, the role the extension gave the field in the page, and `bench_id`).
pub fn rows_for(site: &Site, index: usize, analysis: &Value) -> Vec<Value> {
    let truth = analysis
        .get("truth")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let feature_version = analysis.get("featureVersion").cloned().unwrap_or(json!(1));
    let framework = analysis
        .get("framework")
        .and_then(Value::as_str)
        .unwrap_or("other")
        .to_string();
    let mut out = Vec::new();
    for t in &site.fields {
        if !ROW_TARGETS.contains(&t.role.as_str()) {
            continue;
        }
        let Some(obs) = truth
            .iter()
            .find(|o| o.get("selector").and_then(Value::as_str) == Some(&t.selector))
        else {
            continue;
        };
        let Some(features) = obs.get("features").and_then(Value::as_object) else {
            continue;
        };
        let mut row: Map<String, Value> = features.clone();
        row.remove("lab");
        let detected = obs
            .get("detected")
            .and_then(Value::as_str)
            .map(label_of)
            .unwrap_or("none");
        for (k, v) in [
            ("seed", json!(ROWS_SEED)),
            ("generator", json!(0)),
            ("featureVersion", feature_version.clone()),
            ("site", json!(index)),
            ("step", json!(0)),
            ("source", json!("rendered")),
            ("origin", json!(site.host())),
            ("split", json!("real_test")),
            ("lang", json!(site.lang)),
            ("framework", json!(framework)),
            ("traits", json!([])),
            ("target", json!(t.role)),
            ("accept", json!(t.accept)),
            ("heuristic", json!(detected)),
            ("bench_id", json!(site.id)),
            ("kind", json!(site.kind)),
        ] {
            row.insert(k.to_string(), v);
        }
        out.push(Value::Object(row));
    }
    out
}

pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn recording_path(dir: &Path, site: &Site) -> PathBuf {
    dir.join(format!("{}.html", site.id))
}

/// A page target with its session, closed on drop by the caller through [`close`].
struct Tab {
    target: String,
    session: String,
}

fn open_tab(cdp: &mut Cdp) -> Result<Tab, CdpError> {
    let t = cdp.call(
        None,
        "Target.createTarget",
        json!({"url": "about:blank"}),
        CALL,
    )?;
    let target = t["targetId"].as_str().unwrap_or("").to_string();
    let a = cdp.call(
        None,
        "Target.attachToTarget",
        json!({"targetId": target, "flatten": true}),
        CALL,
    )?;
    let session = a["sessionId"].as_str().unwrap_or("").to_string();
    let s = Some(session.as_str());
    cdp.call(s, "Page.enable", json!({}), CALL)?;
    cdp.call(
        s,
        "Fetch.enable",
        json!({"patterns": [{"urlPattern": "*"}]}),
        CALL,
    )?;
    cdp.call(
        s,
        "Page.addScriptToEvaluateOnNewDocument",
        json!({"source": MAIN_WORLD_GUARD}),
        CALL,
    )?;
    Ok(Tab { target, session })
}

fn close(cdp: &mut Cdp, tab: &Tab) {
    let _ = cdp.call(
        None,
        "Target.closeTarget",
        json!({"targetId": tab.target}),
        CALL,
    );
}

/// Navigates and waits for load plus a quiet time. `Err` carries a load error text.
fn load(cdp: &mut Cdp, tab: &Tab, url: &str) -> Result<(), String> {
    cdp.clear_events();
    let s = Some(tab.session.as_str());
    let nav = cdp
        .call(s, "Page.navigate", json!({"url": url}), CALL)
        .map_err(|e| e.to_string())?;
    if let Some(err) = nav.get("errorText").and_then(Value::as_str) {
        return Err(err.to_string());
    }
    // A page that never fires load (long polling) is still measured after the timeout.
    let _ = cdp.wait_event(&tab.session, "Page.loadEventFired", LOAD);
    cdp.pump(QUIET).map_err(|e| e.to_string())
}

fn eval(cdp: &mut Cdp, tab: &Tab, ctx: Option<i64>, expr: &str) -> Result<Value, String> {
    let mut params = json!({"expression": expr, "awaitPromise": true, "returnByValue": true});
    if let Some(c) = ctx {
        params["contextId"] = json!(c);
    }
    let r = cdp
        .call(Some(&tab.session), "Runtime.evaluate", params, CALL)
        .map_err(|e| e.to_string())?;
    if let Some(ex) = r.get("exceptionDetails") {
        let text = ex["exception"]["description"]
            .as_str()
            .or_else(|| ex["text"].as_str())
            .unwrap_or("exception");
        return Err(text.lines().next().unwrap_or("exception").to_string());
    }
    Ok(r["result"]["value"].clone())
}

/// Isolated world holding the probe (a content script's world: same DOM, own globals).
fn probe_world(cdp: &mut Cdp, tab: &Tab, probe_js: &str) -> Result<i64, String> {
    let s = Some(tab.session.as_str());
    let tree = cdp
        .call(s, "Page.getFrameTree", json!({}), CALL)
        .map_err(|e| e.to_string())?;
    let frame = tree["frameTree"]["frame"]["id"].as_str().unwrap_or("");
    let w = cdp
        .call(
            s,
            "Page.createIsolatedWorld",
            json!({"frameId": frame, "worldName": WORLD}),
            CALL,
        )
        .map_err(|e| e.to_string())?;
    let ctx = w["executionContextId"]
        .as_i64()
        .ok_or("no isolated world")?;
    eval(cdp, tab, Some(ctx), probe_js)?;
    eval(
        cdp,
        tab,
        Some(ctx),
        "globalThis.__onepassProbe = globalThis.__onepassBench.createProbe(); true",
    )?;
    Ok(ctx)
}

fn parse_json(v: Value) -> Result<Value, String> {
    match v {
        Value::String(s) => serde_json::from_str(&s).map_err(|e| e.to_string()),
        other => Ok(other),
    }
}

/// robots.txt of the site's host, read by the browser itself (one GET).
fn robots_allows(cdp: &mut Cdp, tab: &Tab, site: &Site) -> Result<bool, String> {
    let url = format!("https://{}/robots.txt", site.host());
    if load(cdp, tab, &url).is_err() {
        // Unreachable robots.txt: RFC 9309 treats it as no restriction.
        return Ok(true);
    }
    let v = eval(
        cdp,
        tab,
        None,
        r#"(() => { const n = performance.getEntriesByType("navigation")[0];
          const status = n && n.responseStatus ? n.responseStatus : 0;
          const text = document.contentType === "text/plain" && document.body ? document.body.innerText : "";
          return JSON.stringify({ status, text }); })()"#,
    )?;
    let v = parse_json(v)?;
    let status = v["status"].as_u64().unwrap_or(0);
    if status >= 500 {
        return Ok(false);
    }
    if !(200..300).contains(&status) {
        return Ok(true);
    }
    let robots = Robots::parse(v["text"].as_str().unwrap_or(""));
    Ok(robots.allowed(AGENT, site.path()))
}

pub struct SiteRun {
    pub score: SiteScore,
    pub rows: Vec<Value>,
    pub refused: Vec<(String, String)>,
    pub recording: Option<String>,
}

fn bench_site(cdp: &mut Cdp, cfg: &RunConfig, index: usize, site: &Site) -> SiteRun {
    let mut run = SiteRun {
        score: unscored(site, Status::LoadError, None),
        rows: Vec::new(),
        refused: Vec::new(),
        recording: None,
    };
    cdp.source = match cfg.mode {
        Mode::Live => Source::Live,
        Mode::Offline => match std::fs::read_to_string(recording_path(&cfg.recordings, site)) {
            Ok(html) => Source::Offline {
                url: site.url.clone(),
                html,
            },
            Err(_) => {
                run.score = unscored(site, Status::LoadError, Some("no recording".into()));
                return run;
            }
        },
    };
    let tab = match open_tab(cdp) {
        Ok(t) => t,
        Err(e) => {
            run.score = unscored(site, Status::ProbeError, Some(e.to_string()));
            return run;
        }
    };
    let result = (|| -> Result<(), (Status, String)> {
        if cfg.mode == Mode::Live {
            let ok = robots_allows(cdp, &tab, site).map_err(|e| (Status::ProbeError, e))?;
            if !ok {
                return Err((Status::SkippedRobots, "robots.txt".into()));
            }
        }
        load(cdp, &tab, &site.url).map_err(|e| (Status::LoadError, e))?;
        let ctx = probe_world(cdp, &tab, &cfg.probe_js).map_err(|e| (Status::ProbeError, e))?;
        let selectors: Vec<&str> = site.fields.iter().map(|f| f.selector.as_str()).collect();
        let analysis = eval(
            cdp,
            &tab,
            Some(ctx),
            &format!(
                "JSON.stringify(globalThis.__onepassProbe.analyze({}))",
                json!(selectors)
            ),
        )
        .and_then(parse_json)
        .map_err(|e| (Status::ProbeError, e))?;
        run.rows = rows_for(site, index, &analysis);
        let planned: Option<Planned> = plan_for(&analysis["context"], site.kind).ok();
        if let Some(p) = &planned {
            for g in &p.groups {
                let groups = json!([{"form_ref": g.form_ref, "fields": g.fields}]);
                eval(
                    cdp,
                    &tab,
                    Some(ctx),
                    &format!(
                        "globalThis.__onepassProbe.fill({groups}, {})",
                        values_for(g.generated)
                    ),
                )
                .map_err(|e| (Status::ProbeError, e))?;
            }
        }
        let expect: Vec<Value> = site
            .fields
            .iter()
            .map(|f| json!({"selector": f.selector, "expect": expected_values(site.kind, &f.role)}))
            .collect();
        let back = eval(
            cdp,
            &tab,
            Some(ctx),
            &format!(
                "JSON.stringify(globalThis.__onepassProbe.readback({}))",
                Value::Array(expect)
            ),
        )
        .and_then(parse_json)
        .map_err(|e| (Status::ProbeError, e))?;
        let detected: BTreeMap<String, Option<String>> = analysis["truth"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|o| {
                        (
                            o["selector"].as_str().unwrap_or("").to_string(),
                            o["detected"].as_str().map(str::to_string),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let observed: Vec<Observed> = back
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|r| {
                        let sel = r["selector"].as_str().unwrap_or("").to_string();
                        Observed {
                            detected: detected.get(&sel).cloned().flatten(),
                            selector: sel,
                            found: r["found"].as_bool().unwrap_or(false),
                            filled: r["filled"].as_bool().unwrap_or(false),
                            expected_value: r["expected_value"].as_bool().unwrap_or(false),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        run.score = score_site(site, &observed, planned.map(|p| p.summary));
        if cfg.record && cfg.mode == Mode::Live {
            // Pruned after the fill would keep fake values out anyway: prune drops every value.
            let html = eval(
                cdp,
                &tab,
                Some(ctx),
                "globalThis.__onepassBench.prune(document)",
            )
            .map_err(|e| (Status::ProbeError, e))?;
            run.recording = html.as_str().map(str::to_string);
        }
        Ok(())
    })();
    if let Err((status, e)) = result {
        run.score = unscored(site, status, Some(e));
    }
    // Let pending interceptions settle, then collect what was refused.
    let _ = cdp.pump(Duration::from_millis(300));
    run.refused = cdp.take_refused();
    close(cdp, &tab);
    run
}

/// The fields of a live page for writing a truth (robots.txt respected, nothing filled).
pub fn survey(cdp: &mut Cdp, site: &Site, probe_js: &str) -> Result<Vec<Value>, String> {
    let tab = open_tab(cdp).map_err(|e| e.to_string())?;
    let r = (|| {
        if !robots_allows(cdp, &tab, site)? {
            return Err("robots.txt disallows this page".to_string());
        }
        load(cdp, &tab, &site.url)?;
        let ctx = probe_world(cdp, &tab, probe_js)?;
        let v = eval(
            cdp,
            &tab,
            Some(ctx),
            "JSON.stringify(globalThis.__onepassProbe.survey())",
        )
        .and_then(parse_json)?;
        Ok(v.as_array().cloned().unwrap_or_default())
    })();
    close(cdp, &tab);
    r
}

pub struct RunOutput {
    pub report: Report,
    pub rows: Vec<Value>,
    pub recordings: Vec<(String, String)>,
    /// Non-GET requests the interceptor refused, by site (method and URL without query).
    pub refused: BTreeMap<String, Vec<String>>,
}

pub fn run(cdp: &mut Cdp, cfg: &RunConfig, chrome_version: &str) -> RunOutput {
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut scores = Vec::new();
    let mut rows = Vec::new();
    let mut recordings = Vec::new();
    let mut refused = BTreeMap::new();
    let mut last: Option<Instant> = None;
    for (index, site) in cfg.sites.sites.iter().enumerate() {
        if cfg.only.as_deref().is_some_and(|o| o != site.id) {
            continue;
        }
        if cfg.mode == Mode::Live
            && let Some(t) = last
        {
            let wait = cfg.delay.saturating_sub(t.elapsed());
            let _ = cdp.pump(wait);
        }
        last = Some(Instant::now());
        eprintln!("{} {}", site.id, site.url);
        let r = bench_site(cdp, cfg, index, site);
        eprintln!(
            "  {:?} detection={} fill={}{}",
            r.score.status,
            r.score.detection_pass,
            r.score.fill_pass,
            r.score
                .error
                .as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        );
        let posts: Vec<String> = r
            .refused
            .iter()
            .filter(|(m, _)| m != "GET" && m != "HEAD")
            .map(|(m, u)| format!("{m} {}", u.split('?').next().unwrap_or(u)))
            .collect();
        if !posts.is_empty() {
            refused.insert(site.id.clone(), posts);
        }
        if let Some(h) = r.recording {
            recordings.push((site.id.clone(), h));
        }
        rows.extend(r.rows);
        scores.push(r.score);
    }
    let mode = match cfg.mode {
        Mode::Live => "live",
        Mode::Offline => "offline",
    };
    RunOutput {
        report: Report::new(
            mode,
            started,
            chrome_version,
            &sha256_hex(&cfg.probe_js),
            scores,
        ),
        rows,
        recordings,
        refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sites::TruthField;

    fn site() -> Site {
        Site {
            id: "ex-login".into(),
            url: "https://ex.example/login".into(),
            kind: Kind::Login,
            lang: "en".into(),
            fields: vec![
                TruthField {
                    selector: "#u".into(),
                    role: "username".into(),
                    accept: vec!["email".into()],
                },
                TruthField {
                    selector: "#p".into(),
                    role: "password".into(),
                    accept: vec![],
                },
                TruthField {
                    selector: "#n".into(),
                    role: "full_name".into(),
                    accept: vec![],
                },
                TruthField {
                    selector: "#gone".into(),
                    role: "none".into(),
                    accept: vec![],
                },
            ],
        }
    }

    #[test]
    fn expected_values_by_kind_and_role() {
        assert_eq!(
            expected_values(Kind::Login, "email"),
            vec![FAKE_USERNAME, FAKE_EMAIL]
        );
        assert_eq!(
            expected_values(Kind::Login, "password"),
            vec![FAKE_PASSWORD]
        );
        assert_eq!(
            expected_values(Kind::Signup, "new_password"),
            vec![FAKE_NEW_PASSWORD]
        );
        assert!(expected_values(Kind::Signup, "email").is_empty());
        assert!(expected_values(Kind::Login, "none").is_empty());
        assert_eq!(values_for(true)["confirm_password"], FAKE_NEW_PASSWORD);
        assert_eq!(values_for(false)["current_password"], FAKE_PASSWORD);
    }

    #[test]
    fn rows_carry_target_heuristic_and_no_lab_mark() {
        let analysis = json!({
            "featureVersion": 1, "framework": "react",
            "truth": [
                {"selector": "#u", "found": true, "detected": "email", "features": {"index": 0, "tag": "input", "name": "login", "lab": "3"}},
                {"selector": "#p", "found": true, "detected": "current_password", "features": {"index": 1, "tag": "input", "type": "password"}},
                {"selector": "#n", "found": true, "detected": "full_name", "features": {"index": 2, "tag": "input"}},
                {"selector": "#gone", "found": false, "detected": null, "features": null}
            ]
        });
        let rows = rows_for(&site(), 7, &analysis);
        assert_eq!(
            rows.len(),
            2,
            "full_name has no model label, #gone has no features"
        );
        assert_eq!(rows[0]["target"], "username");
        assert_eq!(rows[0]["heuristic"], "email");
        assert_eq!(rows[0]["accept"], json!(["email"]));
        assert_eq!(rows[0]["origin"], "ex.example");
        assert_eq!(rows[0]["site"], 7);
        assert_eq!(rows[0]["framework"], "react");
        assert_eq!(rows[0]["seed"], ROWS_SEED);
        assert!(rows[0].get("lab").is_none());
        assert_eq!(rows[1]["heuristic"], "password");
        let text = serde_json::to_string(&rows).unwrap();
        for v in [FAKE_PASSWORD, FAKE_NEW_PASSWORD, FAKE_EMAIL] {
            assert!(!text.contains(v));
        }
    }

    #[test]
    fn guard_and_digest() {
        assert!(MAIN_WORLD_GUARD.contains("requestSubmit"));
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
