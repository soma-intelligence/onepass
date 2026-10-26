//! KeePass 2 XML export (spec 4.3), read as a stream.
//!
//! `Root/Group` is recursive: the root group name is not part of the folder
//! path, the names of the groups below it are joined by `/`. A group whose
//! `UUID` equals `Meta/RecycleBinUUID` (and every group below it) is
//! skipped. `History` entries are old versions, not items. Only the five
//! predefined entities and character references are decoded: any other
//! entity reference is refused, so a DTD cannot expand anything.

// `parse_keepass_xml` is consumed by the import dispatcher (task 9).
#![allow(dead_code)]

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use crate::Error;
use crate::error::Result;
use crate::model::ItemType;

use super::build::Draft;
use super::limits::{MAX_INPUT, MAX_RECORDS, XML_MAX_DEPTH};
use super::{Import, Warning};

const BAD: Error = Error::InvalidFormat("keepass xml syntax");

/// A group on the path from the root.
struct Frame {
    name: String,
    recycle: bool,
}

/// An entry being read. Holds secrets: no `Debug`.
#[derive(Default)]
struct Acc {
    title: String,
    user: String,
    password: Zeroizing<String>,
    url: String,
    notes: String,
    otp: Zeroizing<String>,
    otp_b32: Zeroizing<String>,
    extras: Vec<(String, Zeroizing<String>, bool)>,
    tags: String,
    binaries: u32,
    expires: bool,
    expiry: String,
    created: String,
    updated: String,
    key: String,
    value: Zeroizing<String>,
    protected: bool,
}

#[derive(Default)]
struct State {
    path: Vec<String>,
    text: Zeroizing<String>,
    recycle_uuid: String,
    frames: Vec<Frame>,
    entry: Option<Acc>,
    history: usize,
    count: usize,
    value_protected: bool,
    out: Import,
}

/// KeePass 2 XML: entries of `Root/Group` as logins. Depth over 256 or
/// more than a million entries is `InvalidFormat`.
pub(crate) fn parse_keepass_xml(b: &[u8]) -> Result<Import> {
    if b.len() > MAX_INPUT {
        return Err(Error::InvalidFormat("import file too large"));
    }
    let b = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
    let text =
        std::str::from_utf8(b).map_err(|_| Error::InvalidFormat("keepass xml is not utf-8"))?;
    let mut reader = Reader::from_str(text);
    let mut st = State::default();
    let mut seen_root = false;
    loop {
        match reader.read_event().map_err(|_| BAD)? {
            Event::Start(e) => {
                seen_root = true;
                st.start(&e)?;
            }
            Event::Empty(e) => {
                seen_root = true;
                st.start(&e)?;
                st.end()?;
            }
            Event::End(_) => st.end()?,
            Event::Text(t) => st.text.push_str(&t.xml10_content()),
            Event::CData(t) => st.text.push_str(&t.xml10_content()),
            Event::GeneralRef(r) => {
                if let Some(c) = r.resolve_char_ref().map_err(|_| BAD)? {
                    st.text.push(c);
                } else {
                    st.text.push(match &*r {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => return Err(Error::InvalidFormat("keepass xml entity")),
                    });
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !seen_root || !st.path.is_empty() {
        return Err(BAD);
    }
    Ok(st.out)
}

impl State {
    fn parent(&self, up: usize) -> &str {
        self.path
            .len()
            .checked_sub(up + 1)
            .and_then(|i| self.path.get(i))
            .map_or("", String::as_str)
    }

    fn start(&mut self, e: &BytesStart<'_>) -> Result<()> {
        let name = e.name().as_ref().to_owned();
        self.path.push(name);
        if self.path.len() > XML_MAX_DEPTH {
            return Err(Error::InvalidFormat("keepass xml too deep"));
        }
        self.text.clear();
        let name = self.parent(0).to_owned();
        match name.as_str() {
            "History" if self.entry.is_some() => self.history += 1,
            _ if self.history > 0 => {}
            "Group" if self.entry.is_none() => {
                let recycle = self.frames.last().is_some_and(|f| f.recycle);
                self.frames.push(Frame {
                    name: String::new(),
                    recycle,
                });
            }
            "Entry" if self.entry.is_none() => self.entry = Some(Acc::default()),
            "Value" if self.entry.is_some() && self.parent(1) == "String" => {
                self.value_protected = false;
                for a in e.attributes().with_checks(false) {
                    let a = a.map_err(|_| BAD)?;
                    if a.key.as_ref() == "Protected" {
                        let v = a
                            .normalized_value(XmlVersion::Implicit1_0)
                            .map_err(|_| BAD)?;
                        self.value_protected = v.trim().eq_ignore_ascii_case("true");
                    }
                }
            }
            "Binary" if self.parent(1) == "Entry" => {
                if let Some(acc) = self.entry.as_mut() {
                    acc.binaries = acc.binaries.saturating_add(1);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn end(&mut self) -> Result<()> {
        let name = self.parent(0).to_owned();
        let parent = self.parent(1).to_owned();
        let grand = self.parent(2).to_owned();
        let text = std::mem::take(&mut self.text);
        if name == "History" && self.entry.is_some() && self.history > 0 {
            self.history -= 1;
        } else if self.history == 0 {
            self.leaf(&name, &parent, &grand, &text)?;
        }
        self.path.pop();
        Ok(())
    }

    fn leaf(&mut self, name: &str, parent: &str, grand: &str, text: &str) -> Result<()> {
        if name == "RecycleBinUUID" && parent == "Meta" {
            text.trim().clone_into(&mut self.recycle_uuid);
            return Ok(());
        }
        let Some(acc) = self.entry.as_mut() else {
            match (name, parent) {
                ("Name", "Group") => {
                    if let Some(f) = self.frames.last_mut() {
                        text.trim().clone_into(&mut f.name);
                    }
                }
                ("UUID", "Group") => {
                    let uuid = text.trim();
                    if !self.recycle_uuid.is_empty()
                        && uuid == self.recycle_uuid
                        && let Some(f) = self.frames.last_mut()
                    {
                        f.recycle = true;
                    }
                }
                ("Group", _) => {
                    self.frames.pop();
                }
                _ => {}
            }
            return Ok(());
        };
        match (name, parent) {
            ("Key", "String") => text.clone_into(&mut acc.key),
            ("Value", "String") => {
                acc.value = Zeroizing::new(text.to_owned());
                acc.protected = self.value_protected;
            }
            ("String", "Entry") => {
                let key = std::mem::take(&mut acc.key);
                let value = std::mem::take(&mut acc.value);
                let protected = acc.protected;
                acc.protected = false;
                match key.as_str() {
                    "Title" => value.as_str().clone_into(&mut acc.title),
                    "UserName" => value.as_str().clone_into(&mut acc.user),
                    "Password" => acc.password = value,
                    "URL" => value.as_str().clone_into(&mut acc.url),
                    "Notes" => value.as_str().clone_into(&mut acc.notes),
                    "otp" => acc.otp = value,
                    "TimeOtp-Secret-Base32" => acc.otp_b32 = value,
                    _ => acc.extras.push((key, value, protected)),
                }
            }
            ("Tags", "Entry") => text.clone_into(&mut acc.tags),
            ("Expires", "Times") if grand == "Entry" => {
                acc.expires = text.trim().eq_ignore_ascii_case("true");
            }
            ("ExpiryTime", "Times") if grand == "Entry" => text.trim().clone_into(&mut acc.expiry),
            ("CreationTime", "Times") if grand == "Entry" => {
                text.trim().clone_into(&mut acc.created);
            }
            ("LastModificationTime", "Times") if grand == "Entry" => {
                text.trim().clone_into(&mut acc.updated);
            }
            ("Entry", _) => self.finish_entry()?,
            _ => {}
        }
        Ok(())
    }

    fn finish_entry(&mut self) -> Result<()> {
        let Some(acc) = self.entry.take() else {
            return Ok(());
        };
        let index = u32::try_from(self.count).unwrap_or(u32::MAX);
        self.count += 1;
        if self.count > MAX_RECORDS {
            return Err(Error::InvalidFormat("too many keepass entries"));
        }
        if self.frames.last().is_some_and(|f| f.recycle) {
            self.out.skipped += 1;
            return Ok(());
        }
        let mut d = Draft::new(ItemType::Login);
        d.title(&acc.title);
        d.set("username", &acc.user);
        d.set("password", &acc.password);
        d.url(&acc.url);
        d.notes(&acc.notes);
        match (acc.otp.trim().is_empty(), acc.otp_b32.trim().is_empty()) {
            (false, _) => {
                d.set("totp", &acc.otp);
                d.extra("TimeOtp-Secret-Base32", &acc.otp_b32, true);
            }
            (true, _) => d.set("totp", &acc.otp_b32),
        }
        for (key, value, protected) in &acc.extras {
            d.extra(key, value, *protected);
        }
        for tag in acc.tags.split([',', ';']) {
            d.tag(tag);
        }
        let folder: Vec<&str> = self
            .frames
            .iter()
            .skip(1)
            .map(|f| f.name.as_str())
            .filter(|n| !n.is_empty())
            .collect();
        d.folder(&folder.join("/"));
        if let Some(t) = rfc3339(&acc.created) {
            d.created(t);
        }
        if let Some(t) = rfc3339(&acc.updated) {
            d.updated(t);
        }
        if acc.expires && !acc.expiry.is_empty() {
            match rfc3339(&acc.expiry) {
                Some(t) => d.expires(t.date()),
                None => d.bad_value("ExpiryTime", &acc.expiry),
            }
        }
        for _ in 0..acc.binaries {
            self.out.warnings.push(Warning {
                entry: index,
                code: "attachment_skipped",
            });
        }
        d.finish(index, &mut self.out);
        Ok(())
    }
}

fn rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s.trim(), &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldValue, Item};

    const KP: &[u8] = include_bytes!("../../tests/fixtures/import/keepass.xml");

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(FieldValue::Text(s) | FieldValue::Email(s) | FieldValue::Phone(s)) => s.clone(),
            Some(FieldValue::Password(s) | FieldValue::Concealed(s) | FieldValue::Otp(s)) => {
                s.to_string()
            }
            _ => String::new(),
        }
    }

    fn imported(item: &Item) -> Vec<(String, FieldValue)> {
        item.sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| s.fields.iter().map(|f| (f.label.clone(), f.value.clone())))
            .collect()
    }

    fn by_title<'a>(imp: &'a Import, title: &str) -> &'a super::super::ImportedItem {
        imp.items
            .iter()
            .find(|i| i.item.title == title)
            .expect("item present")
    }

    fn wrap(entries: &str) -> Vec<u8> {
        format!("<KeePassFile><Root><Group><Name>R</Name>{entries}</Group></Root></KeePassFile>")
            .into_bytes()
    }

    #[test]
    fn entries_and_groups() {
        let imp = parse_keepass_xml(KP).unwrap();
        assert_eq!(imp.items.len(), 2);
        let root = by_title(&imp, "Root login");
        assert_eq!(root.folder, None);
        assert_eq!(root.item.item_type, ItemType::Login);
        assert_eq!(text(&root.item, "username"), "alice@example.com");
        assert_eq!(text(&root.item, "password"), "Pw-Root-1");
        assert_eq!(root.item.urls[0].url, "https://example.com/login");
        assert_eq!(root.item.notes, "first line\nsecond & last");
        assert_eq!(root.item.tags, ["web", "work", "shared"]);
        let deep = by_title(&imp, "Deep entry");
        assert_eq!(deep.folder.as_deref(), Some("Work/Servers"));
        assert_eq!(text(&deep.item, "username"), "bob");
        assert!(text(&deep.item, "totp").starts_with("otpauth://totp/"));
        assert!(
            root.item
                .created_at
                .to_string()
                .starts_with("2024-01-02 3:04:05")
        );
    }

    #[test]
    fn recycle_bin_skipped() {
        let imp = parse_keepass_xml(KP).unwrap();
        assert!(
            imp.items
                .iter()
                .all(|i| !i.item.title.starts_with("Trashed"))
        );
        assert_eq!(imp.skipped, 2);
    }

    #[test]
    fn history_not_imported() {
        let imp = parse_keepass_xml(KP).unwrap();
        assert!(imp.items.iter().all(|i| i.item.title != "Root login old"));
        assert_eq!(imp.items.len() as u32 + imp.skipped, 4);
        // The entry after a History block still closes properly.
        assert_eq!(
            by_title(&imp, "Deep entry").folder.as_deref(),
            Some("Work/Servers")
        );
    }

    #[test]
    fn protected_custom_field_concealed() {
        let imp = parse_keepass_xml(KP).unwrap();
        let extras = imported(&by_title(&imp, "Root login").item);
        let get = |l: &str| extras.iter().find(|(k, _)| k == l).map(|(_, v)| v.clone());
        assert!(matches!(
            get("Backup answer"),
            Some(FieldValue::Concealed(_))
        ));
        assert!(matches!(get("Recovery question"), Some(FieldValue::Text(t)) if t == "Blue"));
    }

    #[test]
    fn otp_uri_kept() {
        let imp = parse_keepass_xml(KP).unwrap();
        let uri = text(&by_title(&imp, "Root login").item, "totp");
        assert!(uri.starts_with("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=Example"));
    }

    #[test]
    fn attachment_warning() {
        let imp = parse_keepass_xml(KP).unwrap();
        let n = imp
            .warnings
            .iter()
            .filter(|w| w.code == "attachment_skipped" && w.entry == 0)
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn expiry_read() {
        let imp = parse_keepass_xml(KP).unwrap();
        let exp = by_title(&imp, "Root login").item.expires.unwrap();
        assert_eq!(exp.to_string(), "2030-01-31");
        assert!(by_title(&imp, "Deep entry").item.expires.is_none());
    }

    #[test]
    fn binary_expiry_kept_as_text() {
        let xml = wrap(
            "<Entry><Times><Expires>True</Expires><ExpiryTime>AAAA2wAAAAA=</ExpiryTime></Times>\
             <String><Key>Title</Key><Value>X</Value></String></Entry>",
        );
        let imp = parse_keepass_xml(&xml).unwrap();
        assert!(imp.items[0].item.expires.is_none());
        assert!(imp.warnings.iter().any(|w| w.code == "bad_date"));
    }

    #[test]
    fn empty_title_falls_back() {
        let xml = wrap(
            "<Entry><String><Key>URL</Key><Value>https://example.com/a</Value></String></Entry>",
        );
        let imp = parse_keepass_xml(&xml).unwrap();
        assert_eq!(imp.items[0].item.title, "example.com");
    }

    #[test]
    fn deep_nesting_rejected() {
        let mut xml = String::from("<KeePassFile><Root>");
        for _ in 0..300 {
            xml.push_str("<Group>");
        }
        for _ in 0..300 {
            xml.push_str("</Group>");
        }
        xml.push_str("</Root></KeePassFile>");
        assert!(parse_keepass_xml(xml.as_bytes()).is_err());
    }

    #[test]
    fn entity_not_expanded() {
        let xml = "<?xml version=\"1.0\"?><!DOCTYPE KeePassFile [<!ENTITY x \"EXPANDED\">]>\
            <KeePassFile><Root><Group><Name>R</Name><Entry>\
            <String><Key>Title</Key><Value>a&x;b</Value></String></Entry></Group></Root></KeePassFile>";
        match parse_keepass_xml(xml.as_bytes()) {
            Err(_) => {}
            Ok(imp) => assert!(imp.items.iter().all(|i| !i.item.title.contains("EXPANDED"))),
        }
    }

    #[test]
    fn predefined_and_char_refs_decoded() {
        let xml = wrap(
            "<Entry><String><Key>Title</Key><Value>a&lt;b&#65;&#x42;</Value></String></Entry>",
        );
        let imp = parse_keepass_xml(&xml).unwrap();
        assert_eq!(imp.items[0].item.title, "a<bAB");
    }

    #[test]
    fn malformed_rejected() {
        assert!(parse_keepass_xml(b"<KeePassFile><Root>").is_err());
        assert!(parse_keepass_xml(b"").is_err());
        assert!(parse_keepass_xml(b"\xFF\xFE").is_err());
    }
}
