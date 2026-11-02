//! onepass-bench: real-site autofill bench (spec 2026-11-02-real-site-bench-and-retrain-design.md).
//!
//!   onepass-bench live    --sites bench/sites.json --out <dir> [--only <id>] [--record] [--delay-ms 5000]
//!   onepass-bench offline --sites bench/sites.json --out <dir> [--check <expected.json>] [--pin <expected.json>]
//!   onepass-bench survey  --url <https url>
//!
//! Common: [--chrome <binary>] [--probe extension/dist-bench/probe.js] [--recordings bench/recordings]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use onepass_bench::cdp::{Cdp, Source};
use onepass_bench::chrome::{Chrome, find_chrome};
use onepass_bench::run::{Mode, RunConfig, run};
use onepass_bench::score::{Verdict, regressions, verdicts};
use onepass_bench::sites::SiteList;
use serde_json::json;

struct Args {
    cmd: String,
    flags: BTreeMap<String, String>,
    switches: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it
        .next()
        .ok_or("missing command: live, offline or survey")?;
    let mut flags = BTreeMap::new();
    let mut switches = Vec::new();
    let mut pending: Option<String> = None;
    for a in it {
        if let Some(k) = pending.take() {
            flags.insert(k, a);
            continue;
        }
        match a.strip_prefix("--") {
            Some("record") => switches.push("record".to_string()),
            Some(k) => pending = Some(k.to_string()),
            None => return Err(format!("unexpected argument {a}")),
        }
    }
    if let Some(k) = pending {
        return Err(format!("--{k} needs a value"));
    }
    Ok(Args {
        cmd,
        flags,
        switches,
    })
}

fn write_json(path: &Path, v: &impl serde::Serialize) -> Result<(), String> {
    let text = serde_json::to_string_pretty(v).map_err(|e| e.to_string())? + "\n";
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

fn browser(args: &Args) -> Result<(Chrome, Cdp, String), String> {
    let bin = find_chrome(args.flags.get("chrome").map(Path::new))
        .ok_or("no Chromium: pass --chrome, set CHROME, or install Playwright's chromium")?;
    let chrome = Chrome::launch(&bin)?;
    let mut cdp = Cdp::connect(&chrome.ws_url).map_err(|e| e.to_string())?;
    let v = cdp
        .call(
            None,
            "Browser.getVersion",
            json!({}),
            Duration::from_secs(10),
        )
        .map_err(|e| e.to_string())?;
    let version = v["product"].as_str().unwrap_or("").to_string();
    Ok((chrome, cdp, version))
}

fn probe_js(args: &Args) -> Result<String, String> {
    let p = args
        .flags
        .get("probe")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("extension/dist-bench/probe.js"));
    std::fs::read_to_string(&p).map_err(|e| {
        format!(
            "{}: {e} (build it: cd extension && npm run bench:probe)",
            p.display()
        )
    })
}

fn bench(args: &Args, mode: Mode) -> Result<ExitCode, String> {
    let sites = SiteList::load(Path::new(
        args.flags
            .get("sites")
            .map(String::as_str)
            .unwrap_or("bench/sites.json"),
    ))
    .map_err(|e| e.to_string())?;
    let out = PathBuf::from(args.flags.get("out").ok_or("--out is required")?);
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let recordings = args
        .flags
        .get("recordings")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("bench/recordings"));
    let delay_ms: u64 = args
        .flags
        .get("delay-ms")
        .map(|d| d.parse().map_err(|_| "--delay-ms must be a number"))
        .transpose()?
        .unwrap_or(5000);
    if mode == Mode::Live && delay_ms < 5000 {
        return Err("--delay-ms below 5000 is not allowed on live sites".into());
    }
    let cfg = RunConfig {
        mode,
        sites,
        recordings: recordings.clone(),
        only: args.flags.get("only").cloned(),
        record: args.switches.iter().any(|s| s == "record"),
        delay: Duration::from_millis(delay_ms),
        probe_js: probe_js(args)?,
    };
    let (_chrome, mut cdp, version) = browser(args)?;
    let output = run(&mut cdp, &cfg, &version);
    write_json(&out.join("report.json"), &output.report)?;
    write_json(&out.join("refused.json"), &output.refused)?;
    let mut rows = std::fs::File::create(out.join("rows.jsonl")).map_err(|e| e.to_string())?;
    for r in &output.rows {
        writeln!(rows, "{r}").map_err(|e| e.to_string())?;
    }
    if !output.recordings.is_empty() {
        std::fs::create_dir_all(&recordings).map_err(|e| e.to_string())?;
        for (id, html) in &output.recordings {
            std::fs::write(recordings.join(format!("{id}.html")), html)
                .map_err(|e| e.to_string())?;
        }
    }
    let s = &output.report.summary;
    println!(
        "{} sites, {} scored, {} skipped, {} stale, {} errors; fields {}/{} ({}), merged macro F1 {}; fill {}/{}",
        s.sites,
        s.scored,
        s.skipped,
        s.stale,
        s.errors,
        s.fields_correct,
        s.fields,
        s.detection_accuracy
            .map(|x| format!("{:.1} %", x * 100.0))
            .unwrap_or("n/a".into()),
        s.merged_macro_f1
            .map(|x| format!("{x:.3}"))
            .unwrap_or("n/a".into()),
        s.fill_pass,
        s.scored
    );
    let actual = verdicts(&output.report.sites);
    if let Some(p) = args.flags.get("pin") {
        write_json(Path::new(p), &actual)?;
    }
    if let Some(p) = args.flags.get("check") {
        let text = std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?;
        let expected: BTreeMap<String, Verdict> =
            serde_json::from_str(&text).map_err(|e| format!("{p}: {e}"))?;
        let bad = regressions(&expected, &actual);
        if !bad.is_empty() {
            eprintln!("regressions against {p}: {}", bad.join(", "));
            return Ok(ExitCode::from(1));
        }
        println!("no regression against {p}");
    }
    Ok(ExitCode::SUCCESS)
}

fn survey(args: &Args) -> Result<ExitCode, String> {
    let url = args.flags.get("url").ok_or("--url is required")?;
    if !url.starts_with("https://") {
        return Err("--url must be https".into());
    }
    let probe = probe_js(args)?;
    let (_chrome, mut cdp, _) = browser(args)?;
    cdp.source = Source::Live;
    let site = onepass_bench::sites::Site {
        id: "survey".into(),
        url: url.clone(),
        kind: onepass_bench::sites::Kind::Login,
        lang: String::new(),
        fields: vec![],
    };
    let fields = onepass_bench::run::survey(&mut cdp, &site, &probe)?;
    for f in fields {
        println!("{f}");
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let result = parse_args().and_then(|a| match a.cmd.as_str() {
        "live" => bench(&a, Mode::Live),
        "offline" => bench(&a, Mode::Offline),
        "survey" => survey(&a),
        other => Err(format!("unknown command {other}")),
    });
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("onepass-bench: {e}");
            ExitCode::from(2)
        }
    }
}
