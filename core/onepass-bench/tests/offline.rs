//! Offline run on hostile recorded pages. Needs Chromium (Playwright's, CHROME or none: skipped)
//! and the built probe (extension/dist-bench/probe.js: skipped when absent).

use std::path::{Path, PathBuf};
use std::time::Duration;

use onepass_bench::cdp::Cdp;
use onepass_bench::chrome::{Chrome, find_chrome};
use onepass_bench::run::{Mode, RunConfig, run};
use onepass_bench::score::Status;
use onepass_bench::sites::SiteList;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn offline_run_scores_fills_and_lets_nothing_out() {
    let Some(bin) = find_chrome(None) else {
        eprintln!("skipped: no Chromium");
        return;
    };
    let probe = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extension/dist-bench/probe.js");
    let Ok(probe_js) = std::fs::read_to_string(&probe) else {
        eprintln!("skipped: build the probe first (cd extension && npm run bench:probe)");
        return;
    };
    let chrome = Chrome::launch(&bin).expect("launch");
    let mut cdp = Cdp::connect(&chrome.ws_url).expect("connect");
    let cfg = RunConfig {
        mode: Mode::Offline,
        sites: SiteList::load(&fixtures().join("sites.json")).expect("sites"),
        recordings: fixtures().join("recordings"),
        only: None,
        record: false,
        delay: Duration::ZERO,
        probe_js,
    };
    let out = run(&mut cdp, &cfg, "test");
    let by = |id: &str| out.report.sites.iter().find(|s| s.id == id).unwrap();

    let login = by("trap-login");
    assert_eq!(login.status, Status::Ok, "{login:?}");
    assert!(login.detection_pass, "{login:?}");
    assert!(login.fill_pass, "{login:?}");
    assert_eq!(login.plan.as_ref().unwrap().intent, "login");

    let signup = by("trap-signup");
    assert_eq!(signup.status, Status::Ok, "{signup:?}");
    assert!(signup.fill_pass, "{signup:?}");

    assert_eq!(by("no-recording").status, Status::LoadError);

    // The hostile page tried a POST fetch and a beacon: both were refused before leaving.
    let refused = out
        .refused
        .get("trap-login")
        .expect("refused requests recorded");
    assert!(
        refused
            .iter()
            .any(|r| r.starts_with("POST ") && r.ends_with("/collect")),
        "{refused:?}"
    );
    assert!(refused.iter().all(|r| !r.starts_with("GET ")));

    // Rows: one per truth field, with the in-page heuristic role, never a value.
    assert_eq!(out.rows.len(), 6);
    let text = serde_json::to_string(&out.rows).unwrap();
    assert!(!text.contains("Bench-Fake"));
    assert!(out.rows.iter().all(|r| r.get("heuristic").is_some()));
}
