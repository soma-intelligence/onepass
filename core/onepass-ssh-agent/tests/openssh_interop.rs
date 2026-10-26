//! Interoperability with OpenSSH's `ssh-keygen`. Every test prints a message
//! and returns early when `ssh-keygen` is not installed. All files live in a
//! fresh `TempDir`, and `HOME` points there so `ssh-keygen` never looks at
//! the user's `~/.ssh`.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use data_encoding::BASE64;
use onepass_ssh_agent::keys::{AgentKey, KeyError, KeyType, is_encrypted, verify_signature};
use onepass_ssh_agent::wire::{SSH_AGENT_RSA_SHA2_512, SshReader, SshWriter};
use tempfile::TempDir;

fn have_ssh_keygen() -> bool {
    match Command::new("ssh-keygen")
        .arg("-?")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(_) => true,
        Err(_) => {
            eprintln!("skipping: ssh-keygen not found");
            false
        }
    }
}

fn keygen(dir: &Path, args: &[&str]) -> Output {
    let out = Command::new("ssh-keygen")
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .stdin(Stdio::null())
        .output()
        .expect("run ssh-keygen");
    assert!(
        out.status.success(),
        "ssh-keygen {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// `algorithm base64` of a public key line, without the comment.
fn without_comment(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// RSA 2048 is refused at generation but accepted at import (spec 6.5).
const KEYGEN_TYPES: [(&str, &[&str]); 6] = [
    ("ed25519", &["-t", "ed25519"]),
    ("p256", &["-t", "ecdsa", "-b", "256"]),
    ("p384", &["-t", "ecdsa", "-b", "384"]),
    ("p521", &["-t", "ecdsa", "-b", "521"]),
    ("rsa", &["-t", "rsa", "-b", "3072"]),
    ("rsa2048", &["-t", "rsa", "-b", "2048"]),
];

fn generate_with_keygen(dir: &Path, name: &str, type_args: &[&str], passphrase: &str) {
    let mut args = vec!["-q"];
    args.extend_from_slice(type_args);
    args.extend_from_slice(&["-N", passphrase, "-C", "test key", "-f", name]);
    keygen(dir, &args);
}

#[test]
fn imports_ssh_keygen_keys() {
    if !have_ssh_keygen() {
        return;
    }
    let dir = TempDir::new().unwrap();
    for (name, args) in KEYGEN_TYPES {
        generate_with_keygen(dir.path(), name, args, "");
        let private = fs::read_to_string(dir.path().join(name)).unwrap();
        let public = fs::read_to_string(dir.path().join(format!("{name}.pub"))).unwrap();
        assert!(!is_encrypted(&private));
        let key =
            AgentKey::from_private_text(&private, None).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(key.public_openssh(""), without_comment(&public), "{name}");
    }
}

#[test]
fn imports_encrypted_key() {
    if !have_ssh_keygen() {
        return;
    }
    let dir = TempDir::new().unwrap();
    for (name, args) in [KEYGEN_TYPES[0], KEYGEN_TYPES[1], KEYGEN_TYPES[4]] {
        generate_with_keygen(dir.path(), name, args, "pass phrase");
        let private = fs::read_to_string(dir.path().join(name)).unwrap();
        let public = fs::read_to_string(dir.path().join(format!("{name}.pub"))).unwrap();
        assert!(is_encrypted(&private));
        assert_eq!(
            AgentKey::from_private_text(&private, None).err(),
            Some(KeyError::NeedPassphrase)
        );
        assert_eq!(
            AgentKey::from_private_text(&private, Some("wrong")).err(),
            Some(KeyError::BadPassphrase)
        );
        let key = AgentKey::from_private_text(&private, Some("pass phrase")).unwrap();
        assert_eq!(key.public_openssh(""), without_comment(&public), "{name}");
    }
}

#[test]
fn imports_pem_pkcs8() {
    if !have_ssh_keygen() {
        return;
    }
    let dir = TempDir::new().unwrap();
    for (name, args) in [KEYGEN_TYPES[1], KEYGEN_TYPES[3], KEYGEN_TYPES[4]] {
        generate_with_keygen(dir.path(), name, args, "");
        let public = fs::read_to_string(dir.path().join(format!("{name}.pub"))).unwrap();
        for (format, label) in [
            ("PKCS8", "-----BEGIN PRIVATE KEY-----"),
            (
                "PEM",
                if name == "rsa" {
                    "-----BEGIN RSA PRIVATE KEY-----"
                } else {
                    "-----BEGIN EC PRIVATE KEY-----"
                },
            ),
        ] {
            let copy = format!("{name}.{format}");
            fs::copy(dir.path().join(name), dir.path().join(&copy)).unwrap();
            keygen(
                dir.path(),
                &["-q", "-p", "-m", format, "-P", "", "-N", "", "-f", &copy],
            );
            let text = fs::read_to_string(dir.path().join(&copy)).unwrap();
            assert!(text.contains(label), "{name} {format}: {text}");
            let key = AgentKey::from_private_text(&text, None)
                .unwrap_or_else(|e| panic!("{name} {format}: {e}"));
            assert_eq!(
                key.public_openssh(""),
                without_comment(&public),
                "{name} {format}"
            );
        }
    }
}

fn write_private(path: &Path, text: &str) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

const ALL: [KeyType; 6] = [
    KeyType::Ed25519,
    KeyType::EcdsaP256,
    KeyType::EcdsaP384,
    KeyType::EcdsaP521,
    KeyType::Rsa3072,
    KeyType::Rsa4096,
];

fn generated_keys() -> &'static [(KeyType, AgentKey)] {
    static KEYS: std::sync::OnceLock<Vec<(KeyType, AgentKey)>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        ALL.iter()
            .map(|&t| (t, AgentKey::generate(t).unwrap()))
            .collect()
    })
}

#[test]
fn exported_key_is_accepted_by_ssh_keygen() {
    if !have_ssh_keygen() {
        return;
    }
    let dir = TempDir::new().unwrap();
    for (i, (t, key)) in generated_keys().iter().enumerate() {
        let path = dir.path().join(format!("export{i}"));
        write_private(&path, &key.to_openssh_private("exported").unwrap());
        let out = keygen(dir.path(), &["-y", "-f", path.to_str().unwrap()]);
        let public = String::from_utf8(out.stdout).unwrap();
        assert_eq!(without_comment(&public), key.public_openssh(""), "{t:?}");
        // ssh-keygen prints the same fingerprint.
        let out = keygen(
            dir.path(),
            &["-l", "-E", "sha256", "-f", path.to_str().unwrap()],
        );
        let listing = String::from_utf8(out.stdout).unwrap();
        assert!(listing.contains(&key.fingerprint()), "{t:?}: {listing}");
    }
}

/// SSHSIG signed data (OpenSSH `PROTOCOL.sshsig`), hashed with SHA-512.
fn sshsig_signed_data(namespace: &str, message: &[u8]) -> Vec<u8> {
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, message);
    let mut w = SshWriter::new();
    w.raw(b"SSHSIG")
        .string(namespace.as_bytes())
        .string(b"")
        .string(b"sha512")
        .string(hash.as_ref());
    w.into_vec()
}

fn sshsig_armor(public_blob: &[u8], namespace: &str, signature: &[u8]) -> String {
    let mut w = SshWriter::new();
    w.raw(b"SSHSIG")
        .u32(1)
        .string(public_blob)
        .string(namespace.as_bytes())
        .string(b"")
        .string(b"sha512")
        .string(signature);
    let b64 = BASE64.encode(w.as_slice());
    let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END SSH SIGNATURE-----\n");
    out
}

#[test]
fn signature_verifies_with_ssh_keygen() {
    if !have_ssh_keygen() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let message = b"message signed by the onepass agent\n";
    fs::write(dir.path().join("msg"), message).unwrap();
    for (i, (t, key)) in generated_keys().iter().enumerate() {
        let data = sshsig_signed_data("file", message);
        let sig = key.sign(&data, SSH_AGENT_RSA_SHA2_512).unwrap();
        let sig_path = format!("msg{i}.sig");
        fs::write(
            dir.path().join(&sig_path),
            sshsig_armor(&key.public_blob(), "file", &sig),
        )
        .unwrap();
        let signers = format!("signers{i}");
        fs::write(
            dir.path().join(&signers),
            format!("signer@example.com {}\n", key.public_openssh("")),
        )
        .unwrap();
        let status = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-f", &signers, "-I", "signer@example.com"])
            .args(["-n", "file", "-s", &sig_path])
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .stdin(fs::File::open(dir.path().join("msg")).unwrap())
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{t:?}: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }
}

/// Parses an armored SSHSIG and returns (public blob, namespace, signature).
fn sshsig_parse(text: &str) -> (Vec<u8>, String, Vec<u8>) {
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let bin = BASE64.decode(b64.as_bytes()).unwrap();
    let body = bin.strip_prefix(b"SSHSIG").unwrap();
    let mut r = SshReader::new(body);
    assert_eq!(r.u32().unwrap(), 1);
    let public = r.string().unwrap().to_vec();
    let namespace = r.utf8().unwrap().to_owned();
    r.string().unwrap();
    assert_eq!(r.utf8().unwrap(), "sha512");
    let sig = r.string().unwrap().to_vec();
    r.finish().unwrap();
    (public, namespace, sig)
}

#[test]
fn ssh_keygen_signatures_verify_here() {
    if !have_ssh_keygen() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let message = b"message signed by ssh-keygen\n";
    fs::write(dir.path().join("msg"), message).unwrap();
    for (name, args) in KEYGEN_TYPES {
        generate_with_keygen(dir.path(), name, args, "");
        keygen(
            dir.path(),
            &["-q", "-Y", "sign", "-f", name, "-n", "file", "msg"],
        );
        let text = fs::read_to_string(dir.path().join("msg.sig")).unwrap();
        fs::remove_file(dir.path().join("msg.sig")).unwrap();
        let (public, namespace, sig) = sshsig_parse(&text);
        assert_eq!(namespace, "file");
        let key =
            AgentKey::from_private_text(&fs::read_to_string(dir.path().join(name)).unwrap(), None)
                .unwrap();
        assert_eq!(public, key.public_blob(), "{name}");
        let data = sshsig_signed_data("file", message);
        verify_signature(&public, &data, &sig).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            verify_signature(&public, b"tampered", &sig),
            Err(KeyError::Crypto),
            "{name}"
        );
    }
}
