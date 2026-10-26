//! Host bookmarks against OpenSSH `known_hosts` files (spec 6.4).
//!
//! The agent only learns the host key of a bound connection
//! (`session-bind@openssh.com`), never the host name. A bookmark of the key
//! (its `hosts` field) is shown as the destination when a `known_hosts` line
//! with that host key names a host the bookmark matches.

use aws_lc_rs::hmac;
use data_encoding::BASE64;

/// Bookmarks of `candidates` that `known_hosts` lists with `host_key` (an
/// SSH public key blob). Supported lines: `[marker] hosts keytype base64
/// [comment]`, where `hosts` is a comma-separated list of names or patterns,
/// `[host]:port`, or one hashed `|1|salt|hash` entry (HMAC-SHA1 of the
/// name). A matching `@revoked` line makes the key match nothing; a
/// `@cert-authority` line is ignored. Hashed entries can only be checked
/// against literal bookmarks (no wildcard).
///
/// For a wildcard bookmark, the name found in the file is returned; for a
/// literal one, the bookmark itself. No duplicates, first match order.
pub fn matching_hosts(known_hosts: &str, host_key: &[u8], candidates: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in known_hosts.lines() {
        let Some(entry) = Line::parse(line) else {
            continue;
        };
        if entry.key != host_key {
            continue;
        }
        match entry.marker {
            Some(Marker::Revoked) => return Vec::new(),
            Some(Marker::CertAuthority) => continue,
            None => {}
        }
        for candidate in candidates {
            if let Some(name) = entry.match_candidate(candidate)
                && !out.iter().any(|o| o.eq_ignore_ascii_case(&name))
            {
                out.push(name);
            }
        }
    }
    out
}

/// OpenSSH `Host` pattern match, ASCII case-insensitive: `*` matches any run
/// of characters (empty included), `?` exactly one. A negated pattern
/// (`!...`) is not supported and never matches.
pub fn pattern_matches(host: &str, pattern: &str) -> bool {
    if pattern.starts_with('!') {
        return false;
    }
    let h: Vec<u8> = host.bytes().map(|b| b.to_ascii_lowercase()).collect();
    let p: Vec<u8> = pattern.bytes().map(|b| b.to_ascii_lowercase()).collect();
    glob(&h, &p)
}

/// Iterative glob with single-star backtracking (linear in practice, no
/// recursion on hostile patterns).
fn glob(s: &[u8], p: &[u8]) -> bool {
    let (mut si, mut pi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, si));
            pi += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

fn has_wildcard(s: &str) -> bool {
    s.contains(['*', '?'])
}

enum Marker {
    Revoked,
    CertAuthority,
}

enum Hosts<'a> {
    /// Comma-separated names or patterns, each possibly `!`-negated.
    Plain(Vec<&'a str>),
    /// `|1|salt|hash`, both base64.
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
}

struct Line<'a> {
    marker: Option<Marker>,
    hosts: Hosts<'a>,
    key: Vec<u8>,
}

impl<'a> Line<'a> {
    fn parse(line: &'a str) -> Option<Line<'a>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut fields = line.split_ascii_whitespace();
        let mut first = fields.next()?;
        let marker = if first.starts_with('@') {
            let m = match first {
                "@revoked" => Marker::Revoked,
                "@cert-authority" => Marker::CertAuthority,
                _ => return None,
            };
            first = fields.next()?;
            Some(m)
        } else {
            None
        };
        let _key_type = fields.next()?;
        let key = BASE64.decode(fields.next()?.as_bytes()).ok()?;
        let hosts = if let Some(rest) = first.strip_prefix("|1|") {
            let (salt, hash) = rest.split_once('|')?;
            Hosts::Hashed {
                salt: BASE64.decode(salt.as_bytes()).ok()?,
                hash: BASE64.decode(hash.as_bytes()).ok()?,
            }
        } else {
            Hosts::Plain(first.split(',').filter(|h| !h.is_empty()).collect())
        };
        Some(Line { marker, hosts, key })
    }

    /// The name to report when this line's hosts match `candidate`.
    fn match_candidate(&self, candidate: &str) -> Option<String> {
        if candidate.is_empty() || candidate.starts_with('!') {
            return None;
        }
        match &self.hosts {
            Hosts::Hashed { salt, hash } => {
                if has_wildcard(candidate) {
                    return None;
                }
                let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
                let name = candidate.to_ascii_lowercase();
                hmac::verify(&key, name.as_bytes(), hash)
                    .is_ok()
                    .then(|| candidate.to_owned())
            }
            Hosts::Plain(entries) => {
                let mut found = None;
                for raw in entries {
                    let (negated, entry) = match raw.strip_prefix('!') {
                        Some(e) => (true, e),
                        None => (false, *raw),
                    };
                    let host = strip_port(entry);
                    let hit = if has_wildcard(candidate) {
                        // A wildcard bookmark against a concrete name.
                        !has_wildcard(host) && pattern_matches(host, candidate)
                    } else {
                        pattern_matches(candidate, host)
                    };
                    if !hit {
                        continue;
                    }
                    if negated {
                        // OpenSSH: a matching negation excludes the line.
                        return None;
                    }
                    if found.is_none() {
                        found = Some(if has_wildcard(candidate) {
                            host.to_ascii_lowercase()
                        } else {
                            candidate.to_owned()
                        });
                    }
                }
                found
            }
        }
    }
}

/// `[host]:port` to `host`; anything else unchanged.
fn strip_port(entry: &str) -> &str {
    entry
        .strip_prefix('[')
        .and_then(|r| r.split_once(']'))
        .map_or(entry, |(host, _)| host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{AgentKey, KeyType};

    fn key_line(blob: &[u8]) -> String {
        format!("ssh-ed25519 {}", BASE64.encode(blob))
    }

    fn hashed(name: &str, salt: &[u8]) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let tag = hmac::sign(&key, name.as_bytes());
        format!("|1|{}|{}", BASE64.encode(salt), BASE64.encode(tag.as_ref()))
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn plain_and_hashed_entries_match() {
        let host = AgentKey::generate(KeyType::Ed25519).unwrap().public_blob();
        let other = AgentKey::generate(KeyType::Ed25519).unwrap().public_blob();
        let file = format!(
            "# comment\n\
             plain.example.test,10.0.0.1 {k}\n\
             {h} {k}\n\
             wrong.example.test {o}\n\
             garbage line\n",
            k = key_line(&host),
            o = key_line(&other),
            h = hashed("hashed.example.test", b"0123456789abcdefghij"),
        );
        let found = matching_hosts(
            &file,
            &host,
            &s(&[
                "plain.example.test",
                "hashed.example.test",
                "wrong.example.test",
                "absent.example.test",
            ]),
        );
        assert_eq!(found, s(&["plain.example.test", "hashed.example.test"]));
        // Case-insensitive, no duplicates.
        let found = matching_hosts(
            &file,
            &host,
            &s(&["PLAIN.example.test", "plain.example.test"]),
        );
        assert_eq!(found, s(&["PLAIN.example.test"]));
        // A wildcard bookmark reports the concrete name of a plain entry and
        // cannot match a hashed one.
        let found = matching_hosts(&file, &host, &s(&["*.example.test"]));
        assert_eq!(found, s(&["plain.example.test"]));
        // The other key matches only its own line.
        let found = matching_hosts(
            &file,
            &other,
            &s(&["plain.example.test", "wrong.example.test"]),
        );
        assert_eq!(found, s(&["wrong.example.test"]));
    }

    #[test]
    fn bracketed_port_entry() {
        let host = AgentKey::generate(KeyType::Ed25519).unwrap().public_blob();
        let file = format!("[git.example.test]:2222 {}\n", key_line(&host));
        assert_eq!(
            matching_hosts(&file, &host, &s(&["git.example.test"])),
            s(&["git.example.test"])
        );
        assert_eq!(
            matching_hosts(&file, &host, &s(&["*.example.test"])),
            s(&["git.example.test"])
        );
    }

    #[test]
    fn revoked_marker_excludes() {
        let host = AgentKey::generate(KeyType::Ed25519).unwrap().public_blob();
        let k = key_line(&host);
        let file = format!("git.example.test {k}\n@revoked * {k}\n");
        assert!(matching_hosts(&file, &host, &s(&["git.example.test"])).is_empty());
        let ca = format!("@cert-authority git.example.test {k}\n");
        assert!(matching_hosts(&ca, &host, &s(&["git.example.test"])).is_empty());
        // A negated entry that matches excludes its line.
        let neg = format!("*.example.test,!git.example.test {k}\n");
        assert!(matching_hosts(&neg, &host, &s(&["git.example.test"])).is_empty());
        assert_eq!(
            matching_hosts(&neg, &host, &s(&["www.example.test"])),
            s(&["www.example.test"])
        );
    }

    #[test]
    fn pattern_matches_cases() {
        assert!(pattern_matches("git.example.com", "git.example.com"));
        assert!(pattern_matches("Git.Example.COM", "git.example.com"));
        assert!(pattern_matches("git.example.com", "*.example.com"));
        assert!(!pattern_matches("example.com", "*.example.com"));
        assert!(pattern_matches("a.b.example.com", "*.example.com"));
        assert!(pattern_matches("host1", "host?"));
        assert!(!pattern_matches("host12", "host?"));
        assert!(pattern_matches("anything", "*"));
        assert!(pattern_matches("", "*"));
        assert!(pattern_matches("10.0.0.7", "10.0.0.*"));
        assert!(!pattern_matches("git.example.com", "!git.example.com"));
        assert!(!pattern_matches("other.com", "!git.example.com"));
        assert!(!pattern_matches("git.example.com", "git.example"));
        assert!(pattern_matches("aaaaaaaaaaaaaaaaaaaab", "*a*a*a*a*a*b"));
        assert!(!pattern_matches("aaaaaaaaaaaaaaaaaaaaa", "*a*a*a*a*a*b"));
    }
}
