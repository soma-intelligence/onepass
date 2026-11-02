//! Guard: fresh randomness for secrets comes only from the hedged source
//! (`onepass_core::crypto::random`, see `docs/security.md`, "Randomness").
//!
//! Scans the shipped Rust sources of every workspace crate (`core/*/src`,
//! test modules and `testing/` helpers left out) and the Swift sources under
//! `apple/` (test targets left out) for direct draws from the OS generator,
//! and for library key generation that draws from it internally. Each hit
//! must be in `ALLOWED`, with its reason and its exact number of lines; a new
//! call site fails this test until it goes through the hedged source or is
//! added here with a reason.
//!
//! Nonces also go through the hedged source (`fill_random` is the only
//! function): the allowlist holds only values that are not secrets, crates
//! that cannot depend on the core, and randomness that libraries draw inside
//! an operation where no outside randomness can be given.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Rust patterns: the OS generator, and aws-lc key generation that uses it.
const RUST_PATTERNS: &[&str] = &[
    "aws_lc_rs::rand",
    "SystemRandom",
    "OsRng",
    "getrandom",
    "thread_rng",
    "rand::rng(",
    "rand::random",
    "DecapsulationKey::generate",
    "PrivateKey::generate",
    "KeyPair::generate",
    "generate_pkcs8",
];

/// Swift patterns: system random sources and keys the system generates.
const SWIFT_PATTERNS: &[&str] = &[
    "SecRandomCopyBytes",
    "SystemRandomNumberGenerator",
    ".random(in",
    "randomElement(",
    "arc4random",
    "SymmetricKey(size",
    "PrivateKey()",
    "SecKeyCreateRandomKey",
];

/// (path from the repository root, number of matching lines, reason).
const ALLOWED: &[(&str, usize, &str)] = &[
    (
        "core/onepass-core/src/crypto/random.rs",
        1,
        "the hedged source itself: its OS input",
    ),
    (
        "core/onepass-core/src/webauthn.rs",
        2,
        "SystemRandom passed to ECDSA sign: aws-lc ignores it, the nonce is aws-lc's, \
         hedged with the key and digest",
    ),
    (
        "core/onepass-ssh-agent/src/keys.rs",
        4,
        "SystemRandom passed to ECDSA/RSA sign (aws-lc ignores it and draws inside the \
         operation), and RsaKeyPair::generate: aws-lc draws RSA primes itself and takes no \
         outside randomness (Ed25519 and ECDSA keys use the hedged source)",
    ),
    (
        "core/onepass-ssh-agent/src/openssh.rs",
        1,
        "OpenSSH check integer of an unencrypted key file: not a secret",
    ),
    (
        "core/onepass-guard/src/grants.rs",
        1,
        "grant id (public identifier); the guard cannot depend on the core",
    ),
    (
        "core/onepass-guard/src/control.rs",
        1,
        "control-socket request nonce (freshness, not a secret); no core dependency",
    ),
    (
        "core/onepass-guard/src/approval.rs",
        1,
        "short approval challenge shown to the user; no core dependency",
    ),
    (
        "core/onepass-mailbox/src/client.rs",
        1,
        "request nonce (freshness, not a secret); the mailbox crate cannot depend on the core",
    ),
    (
        "apple/VaultKit/Sources/VaultKit/Remote/RemoteUnlockKeyring.swift",
        1,
        "presence marker item: its content is never read as a secret",
    ),
    (
        "apple/VaultKit/Sources/VaultKit/Biometrics/SecureEnclaveBiometricUnlock.swift",
        1,
        "Secure Enclave key: made and kept inside the enclave, which takes no outside \
         randomness",
    ),
    ("apple/App/Root/DemoData.swift", 1, "Debug demo data only"),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository root")
        .to_path_buf()
}

fn walk(dir: &Path, ext: &str, skip: &dyn Fn(&Path) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if skip(&path) {
            continue;
        }
        if path.is_dir() {
            walk(&path, ext, skip, out);
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

/// Source without its trailing `#[cfg(test)] mod ...` block.
fn shipped_part(text: &str) -> &str {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut offset = 0;
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]"
            && lines[i + 1..]
                .iter()
                .take(2)
                .any(|l| l.trim_start().starts_with("mod "))
        {
            return &text[..offset];
        }
        offset += line.len();
    }
    text
}

fn count_hits(text: &str, patterns: &[&str]) -> usize {
    text.lines()
        .filter(|l| patterns.iter().any(|p| l.contains(p)))
        .count()
}

fn scan() -> BTreeMap<String, usize> {
    let root = repo_root();
    let mut hits = BTreeMap::new();

    let mut rust = Vec::new();
    let core = root.join("core");
    for entry in fs::read_dir(&core).expect("core dir").flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            walk(
                &src,
                "rs",
                &|p| {
                    p.file_name()
                        .is_some_and(|n| n == "testing" || n == "tests")
                },
                &mut rust,
            );
        }
    }
    for path in rust {
        let text = fs::read_to_string(&path).expect("read source");
        let n = count_hits(shipped_part(&text), RUST_PATTERNS);
        if n > 0 {
            let rel = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            hits.insert(rel, n);
        }
    }

    let mut swift = Vec::new();
    walk(
        &root.join("apple"),
        "swift",
        &|p| {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
            name.is_some_and(|n| {
                n.ends_with("Tests")
                    || n == "build"
                    || n == "DerivedData"
                    || n == ".build"
                    || n.starts_with('.')
            })
        },
        &mut swift,
    );
    for path in swift {
        let text = fs::read_to_string(&path).expect("read source");
        let n = count_hits(&text, SWIFT_PATTERNS);
        if n > 0 {
            let rel = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            hits.insert(rel, n);
        }
    }
    hits
}

#[test]
fn randomness_for_secrets_goes_through_the_hedged_source() {
    let hits = scan();
    let allowed: BTreeMap<&str, usize> = ALLOWED.iter().map(|(p, n, _)| (*p, *n)).collect();
    let mut problems = Vec::new();
    for (path, n) in &hits {
        match allowed.get(path.as_str()) {
            Some(want) if want == n => {}
            Some(want) => problems.push(format!(
                "{path}: {n} matching lines, the allowlist says {want}"
            )),
            None => problems.push(format!(
                "{path}: {n} direct draws from the OS generator (use \
                 onepass_core::crypto::random, or allowlist with a reason)"
            )),
        }
    }
    for path in allowed.keys() {
        if !hits.contains_key(*path) {
            problems.push(format!(
                "{path}: allowlisted but no longer matches, remove it"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn guard_catches_a_direct_draw() {
    let src = "fn f() { aws_lc_rs::rand::fill(&mut b).unwrap(); }\n\
               #[cfg(test)]\nmod tests { fn g() { OsRng.fill_bytes(&mut b); } }\n";
    assert_eq!(count_hits(shipped_part(src), RUST_PATTERNS), 1);
    assert_eq!(
        count_hits("let k = SymmetricKey(size: .bits256)", SWIFT_PATTERNS),
        1
    );
}
