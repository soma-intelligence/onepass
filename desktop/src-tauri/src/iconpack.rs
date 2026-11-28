//! Site icons from the icon pack the Apple apps bundle (icon-pack/, a copy
//! of apple/IconPack; sources and licenses in its manifest). Format 1, read
//! as VaultKit `IconPack.swift` does:
//!
//! ```text
//! "OPIP" | u8 format = 1 | u32 BE index length L | L bytes of JSON index | blob
//! index: {"domains": {host: n}, "names": {squashed: n}, "tenants": [host],
//!         "icons": [[offset, length, flags]], "format": 1, "size", "version"}
//! ```
//!
//! Icons are 256 px lossless WebP; flag bit 0 marks a monochrome mark drawn
//! in the text color. Offline: no site is ever contacted for an icon.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde::Deserialize;

static PACK: &[u8] = include_bytes!("../icon-pack/onepass-icons.bin");
const MAX_INDEX: usize = 8 * 1024 * 1024;

#[derive(Deserialize)]
struct Index {
    format: u32,
    domains: HashMap<String, usize>,
    #[serde(default)]
    names: HashMap<String, usize>,
    #[serde(default)]
    tenants: HashSet<String>,
    icons: Vec<(usize, usize, u32)>,
}

pub struct Pack {
    index: Index,
    blob: &'static [u8],
}

pub fn pack() -> Option<&'static Pack> {
    static P: OnceLock<Option<Pack>> = OnceLock::new();
    P.get_or_init(|| parse(PACK)).as_ref()
}

fn parse(bytes: &'static [u8]) -> Option<Pack> {
    let rest = bytes.strip_prefix(b"OPIP")?;
    let (&format, rest) = rest.split_first()?;
    let (len, rest) = rest.split_at_checked(4)?;
    let len = usize::try_from(u32::from_be_bytes(len.try_into().ok()?)).ok()?;
    if format != 1 || len > MAX_INDEX {
        return None;
    }
    let (json, blob) = rest.split_at_checked(len)?;
    let index: Index = serde_json::from_slice(json).ok()?;
    let n = index.icons.len();
    let valid = index.format == 1
        && index
            .icons
            .iter()
            .all(|&(off, l, _)| l > 0 && off.checked_add(l).is_some_and(|end| end <= blob.len()))
        && index
            .domains
            .values()
            .chain(index.names.values())
            .all(|&i| i < n);
    valid.then_some(Pack { index, blob })
}

impl Pack {
    /// The icon of a host: the host, then its parents down to the
    /// registrable domain; a tenant (auth0.com...) only matches exactly.
    pub fn for_host(&self, host: &str) -> Option<usize> {
        let host = host.trim().trim_end_matches('.').to_lowercase();
        let host = host.strip_prefix("www.").unwrap_or(&host);
        let labels: Vec<&str> = host.split('.').collect();
        if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
            return None;
        }
        let floor = onepass_ffi::registrable_domain(host.to_owned())
            .map_or(2, |d| d.split('.').count())
            .max(2);
        for start in 0..labels.len() {
            if labels.len() - start < floor {
                break;
            }
            let candidate = labels[start..].join(".");
            if start > 0 && self.index.tenants.contains(&candidate) {
                continue;
            }
            if let Some(&i) = self.index.domains.get(&candidate) {
                return Some(i);
            }
        }
        None
    }

    /// The icon of a title: a host-like title first, then the brand name.
    pub fn for_title(&self, title: &str) -> Option<usize> {
        let t = title.trim().to_lowercase();
        if !t.contains(' ')
            && t.contains('.')
            && let Some(i) = self.for_host(&t)
        {
            return Some(i);
        }
        let key = squash(&t);
        if key.len() < 3 {
            return None;
        }
        self.index.names.get(&key).copied()
    }

    /// The WebP bytes and whether the mark is monochrome.
    pub fn image(&self, i: usize) -> Option<(&'static [u8], bool)> {
        let &(off, len, flags) = self.index.icons.get(i)?;
        Some((self.blob.get(off..off + len)?, flags & 1 == 1))
    }
}

/// Lower case, "&" as "and", accents dropped, only a-z and 0-9 kept.
fn squash(s: &str) -> String {
    let mut out = String::new();
    for c in s.to_lowercase().replace('&', "and").chars() {
        let base = match c {
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
            'ç' => 'c',
            'è' | 'é' | 'ê' | 'ë' => 'e',
            'ì' | 'í' | 'î' | 'ï' => 'i',
            'ñ' => 'n',
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' => 'o',
            'ù' | 'ú' | 'û' | 'ü' => 'u',
            'ý' | 'ÿ' => 'y',
            'œ' => {
                out.push('o');
                'e'
            }
            'æ' => {
                out.push('a');
                'e'
            }
            'ß' => {
                out.push('s');
                's'
            }
            c => c,
        };
        if base.is_ascii_lowercase() || base.is_ascii_digit() {
            out.push(base);
        }
    }
    out
}

/// The host of a website as typed in an item ("github.com/login" too).
pub fn host_of(url: &str) -> Option<String> {
    let u = url.trim();
    let with_scheme = if u.contains("://") {
        u.to_owned()
    } else {
        format!("https://{u}")
    };
    url::Url::parse(&with_scheme)
        .ok()?
        .host_str()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_pack_reads_and_finds_known_sites() {
        let p = pack().expect("the icon pack parses");
        assert!(p.index.icons.len() > 1000);
        let gh = p.for_host("github.com").expect("github.com has an icon");
        assert_eq!(p.for_host("www.github.com"), Some(gh));
        assert!(p.for_host("gist.github.com").is_some());
        let (img, _) = p.image(gh).unwrap();
        assert_eq!(&img[0..4], b"RIFF");
        assert_eq!(&img[8..12], b"WEBP");
        assert!(p.for_title("GitHub").is_some());
        assert_eq!(p.for_host("com"), None);
    }

    #[test]
    fn titles_are_squashed() {
        assert_eq!(squash("Crédit Agricole"), "creditagricole");
        assert_eq!(squash("AT&T"), "atandt");
    }
}
