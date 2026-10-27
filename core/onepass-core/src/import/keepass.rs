//! KeePass 2 XML export (spec 4.3), read as a stream.
//!
//! `Root/Group` is recursive: the root group name is not part of the folder
//! path, the names of the groups below it are joined by `/`. A group whose
//! `UUID` equals `Meta/RecycleBinUUID` (and every group below it) is
//! skipped. `History` entries are old versions, not items. Only the five
//! predefined entities and character references are decoded: any other
//! entity reference is refused, so a DTD cannot expand anything.

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use std::borrow::Cow;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::{Zeroize, Zeroizing};

use crate::Error;
use crate::error::Result;
use crate::model::ItemType;

use super::build::Draft;
use super::limits::{MAX_INPUT, MAX_RECORDS, XML_MAX_DEPTH};
use super::{Import, Warning};

const BAD: Error = Error::InvalidFormat("keepass xml syntax");

/// Meaning of an open element, fixed when it starts from its parent's
/// kind. Everything unexpected, and everything below it, is `Other`: its
/// content is ignored. One kind is pushed per start tag and popped per end
/// tag, so groups and entries always balance.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Meta,
    RecycleBinUuid,
    Root,
    Group,
    GroupName,
    GroupUuid,
    Entry,
    Str,
    Key,
    Value,
    Tags,
    Times,
    Expires,
    ExpiryTime,
    Created,
    Modified,
    Binary,
    History,
    Other,
}

impl Kind {
    fn of(parent: Option<Kind>, name: &str) -> Kind {
        match (parent, name) {
            (None, "KeePassFile") => Kind::File,
            (Some(Kind::File), "Meta") => Kind::Meta,
            (Some(Kind::File), "Root") => Kind::Root,
            (Some(Kind::Meta), "RecycleBinUUID") => Kind::RecycleBinUuid,
            (Some(Kind::Root | Kind::Group), "Group") => Kind::Group,
            (Some(Kind::Group), "Name") => Kind::GroupName,
            (Some(Kind::Group), "UUID") => Kind::GroupUuid,
            (Some(Kind::Group), "Entry") => Kind::Entry,
            (Some(Kind::Entry), "String") => Kind::Str,
            (Some(Kind::Entry), "Tags") => Kind::Tags,
            (Some(Kind::Entry), "Times") => Kind::Times,
            (Some(Kind::Entry), "History") => Kind::History,
            (Some(Kind::Entry), "Binary") => Kind::Binary,
            (Some(Kind::Str), "Key") => Kind::Key,
            (Some(Kind::Str), "Value") => Kind::Value,
            (Some(Kind::Times), "Expires") => Kind::Expires,
            (Some(Kind::Times), "ExpiryTime") => Kind::ExpiryTime,
            (Some(Kind::Times), "CreationTime") => Kind::Created,
            (Some(Kind::Times), "LastModificationTime") => Kind::Modified,
            _ => Kind::Other,
        }
    }

    /// Kinds whose text is read.
    fn has_text(self) -> bool {
        matches!(
            self,
            Kind::RecycleBinUuid
                | Kind::GroupName
                | Kind::GroupUuid
                | Kind::Key
                | Kind::Value
                | Kind::Tags
                | Kind::Expires
                | Kind::ExpiryTime
                | Kind::Created
                | Kind::Modified
        )
    }
}

/// Keys that fill a login field; a second occurrence goes to `imported`.
const STANDARD_KEYS: [&str; 7] = [
    "Title",
    "UserName",
    "Password",
    "URL",
    "Notes",
    "otp",
    "TimeOtp-Secret-Base32",
];

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
    seen: Vec<&'static str>,
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
    stack: Vec<Kind>,
    text: Zeroizing<String>,
    recycle_uuid: String,
    frames: Vec<Frame>,
    entry: Option<Acc>,
    count: usize,
    value_protected: bool,
    out: Import,
}

/// First eight bytes of a KDBX (KeePass 2 binary) file.
pub(crate) const KDBX_MAGIC: [u8; 8] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];

/// KeePass 2 XML: entries of `Root/Group` as logins. Depth over 256 or
/// more than a million entries is `InvalidFormat`. A KDBX file is refused
/// with an explicit message.
pub(crate) fn parse_keepass_xml(b: &[u8]) -> Result<Import> {
    if b.len() > MAX_INPUT {
        return Err(Error::InvalidFormat("import file too large"));
    }
    if b.starts_with(&KDBX_MAGIC) {
        return Err(Error::InvalidFormat(
            "KeePass KDBX is not supported: export as KeePass 2 XML",
        ));
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
                st.start(&e, &mut seen_root)?;
            }
            Event::Empty(e) => {
                st.start(&e, &mut seen_root)?;
                st.end()?;
            }
            Event::End(_) => st.end()?,
            Event::Text(t) => st.push_text(t.xml10_content()),
            Event::CData(t) => st.push_text(t.xml10_content()),
            Event::GeneralRef(r) => {
                let mut buf = [0u8; 4];
                if let Some(c) = r.resolve_char_ref().map_err(|_| BAD)? {
                    st.push_text(Cow::Borrowed(c.encode_utf8(&mut buf)));
                } else {
                    let s = match &*r {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => return Err(Error::InvalidFormat("keepass xml entity")),
                    };
                    st.push_text(Cow::Borrowed(s));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !seen_root || !st.stack.is_empty() {
        return Err(BAD);
    }
    Ok(st.out)
}

impl State {
    fn top(&self) -> Kind {
        self.stack.last().copied().unwrap_or(Kind::Other)
    }

    /// Appends element text when the open element reads text. An owned
    /// temporary is wiped.
    fn push_text(&mut self, t: Cow<'_, str>) {
        if self.top().has_text() {
            self.text.push_str(&t);
        }
        if let Cow::Owned(mut s) = t {
            s.zeroize();
        }
    }

    fn start(&mut self, e: &BytesStart<'_>, seen_root: &mut bool) -> Result<()> {
        let parent = self.stack.last().copied();
        let kind = Kind::of(parent, e.name().as_ref());
        if parent.is_none() {
            if *seen_root {
                return Err(BAD);
            }
            *seen_root = true;
            if kind != Kind::File {
                return Err(Error::InvalidFormat("not a KeePass XML file"));
            }
        }
        self.stack.push(kind);
        if self.stack.len() > XML_MAX_DEPTH {
            return Err(Error::InvalidFormat("keepass xml too deep"));
        }
        if kind.has_text() {
            self.text.clear();
        }
        match kind {
            Kind::Group => {
                let recycle = self.frames.last().is_some_and(|f| f.recycle);
                self.frames.push(Frame {
                    name: String::new(),
                    recycle,
                });
            }
            Kind::Entry => self.entry = Some(Acc::default()),
            Kind::Value => {
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
            Kind::Binary => {
                if let Some(acc) = self.entry.as_mut() {
                    acc.binaries = acc.binaries.saturating_add(1);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn end(&mut self) -> Result<()> {
        let kind = self.stack.pop().ok_or(BAD)?;
        let text = if kind.has_text() {
            std::mem::take(&mut self.text)
        } else {
            Zeroizing::new(String::new())
        };
        let text: &str = &text;
        match kind {
            Kind::RecycleBinUuid => text.trim().clone_into(&mut self.recycle_uuid),
            Kind::GroupName => {
                if let Some(f) = self.frames.last_mut() {
                    text.trim().clone_into(&mut f.name);
                }
            }
            Kind::GroupUuid => {
                if !self.recycle_uuid.is_empty()
                    && text.trim() == self.recycle_uuid
                    && let Some(f) = self.frames.last_mut()
                {
                    f.recycle = true;
                }
            }
            Kind::Group => {
                self.frames.pop();
            }
            Kind::Entry => self.finish_entry()?,
            Kind::Key => {
                if let Some(acc) = self.entry.as_mut() {
                    text.clone_into(&mut acc.key);
                }
            }
            Kind::Value => {
                if let Some(acc) = self.entry.as_mut() {
                    acc.value = Zeroizing::new(text.to_owned());
                    acc.protected = self.value_protected;
                }
            }
            Kind::Str => {
                if let Some(acc) = self.entry.as_mut() {
                    acc.commit();
                }
            }
            Kind::Tags => self.with_entry(|a| text.clone_into(&mut a.tags)),
            Kind::Expires => {
                self.with_entry(|a| a.expires = text.trim().eq_ignore_ascii_case("true"));
            }
            Kind::ExpiryTime => self.with_entry(|a| text.trim().clone_into(&mut a.expiry)),
            Kind::Created => self.with_entry(|a| text.trim().clone_into(&mut a.created)),
            Kind::Modified => self.with_entry(|a| text.trim().clone_into(&mut a.updated)),
            _ => {}
        }
        Ok(())
    }

    fn with_entry(&mut self, f: impl FnOnce(&mut Acc)) {
        if let Some(acc) = self.entry.as_mut() {
            f(acc);
        }
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
        if acc.otp.trim().is_empty() {
            d.set("totp", &acc.otp_b32);
        } else {
            d.set("totp", &acc.otp);
            d.extra("TimeOtp-Secret-Base32", &acc.otp_b32, true);
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
        for (raw, label, apply) in [
            (
                &acc.created,
                "CreationTime",
                Draft::created as fn(&mut Draft, OffsetDateTime),
            ),
            (&acc.updated, "LastModificationTime", Draft::updated),
        ] {
            if !raw.is_empty() {
                match rfc3339(raw) {
                    Some(t) => apply(&mut d, t),
                    None => d.bad_value(label, raw),
                }
            }
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

impl Acc {
    /// Stores the finished `String` element: a login field, or `imported`
    /// for other keys and for a repeated standard key.
    fn commit(&mut self) {
        let key = std::mem::take(&mut self.key);
        let value = std::mem::take(&mut self.value);
        let protected = std::mem::take(&mut self.protected);
        if let Some(std_key) = STANDARD_KEYS.iter().copied().find(|k| *k == key)
            && !self.seen.contains(&std_key)
        {
            self.seen.push(std_key);
            match std_key {
                "Title" => value.as_str().clone_into(&mut self.title),
                "UserName" => value.as_str().clone_into(&mut self.user),
                "Password" => self.password = value,
                "URL" => value.as_str().clone_into(&mut self.url),
                "Notes" => value.as_str().clone_into(&mut self.notes),
                "otp" => self.otp = value,
                _ => self.otp_b32 = value,
            }
            return;
        }
        self.extras.push((key, value, protected));
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
        assert!(parse_keepass_xml(xml.as_bytes()).is_err());
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

    fn nested(groups: usize) -> String {
        let mut xml = String::from("<KeePassFile><Root>");
        for _ in 0..groups {
            xml.push_str("<Group>");
        }
        for _ in 0..groups {
            xml.push_str("</Group>");
        }
        xml.push_str("</Root></KeePassFile>");
        xml
    }

    #[test]
    fn depth_limit_is_exact() {
        // KeePassFile + Root + 254 groups = 256 levels.
        assert!(parse_keepass_xml(nested(254).as_bytes()).is_ok());
        assert!(parse_keepass_xml(nested(255).as_bytes()).is_err());
    }

    #[test]
    fn long_parent_name_is_linear() {
        let name = "a".repeat(64 * 1024);
        let mut xml = format!("<KeePassFile><{name}>");
        for _ in 0..200_000 {
            xml.push_str("<c/>");
        }
        xml.push_str(&format!("</{name}></KeePassFile>"));
        let start = std::time::Instant::now();
        assert!(parse_keepass_xml(xml.as_bytes()).is_ok());
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn group_inside_entry_keeps_stack_balanced() {
        let xml = "<KeePassFile><Meta><RecycleBinUUID>BIN</RecycleBinUUID></Meta><Root>\
            <Group><Name>R</Name><Group><UUID>BIN</UUID><Name>Bin</Name>\
            <Entry><String><Key>Title</Key><Value>a</Value></String>\
            <Group><Entry/></Group></Entry>\
            <Entry><String><Key>Title</Key><Value>b</Value></String></Entry>\
            </Group></Group></Root></KeePassFile>";
        let imp = parse_keepass_xml(xml.as_bytes()).unwrap();
        assert!(imp.items.is_empty());
        assert_eq!(imp.skipped, 2);
    }

    #[test]
    fn nested_entry_outside_history_ignored() {
        let xml = wrap(
            "<Entry><String><Key>Title</Key><Value>outer</Value></String>\
             <Entry><String><Key>Title</Key><Value>inner</Value></String></Entry>\
             <String><Key>UserName</Key><Value>kept</Value></String></Entry>",
        );
        let imp = parse_keepass_xml(&xml).unwrap();
        assert_eq!(imp.items.len(), 1);
        assert_eq!(imp.items[0].item.title, "outer");
        assert_eq!(text(&imp.items[0].item, "username"), "kept");
    }

    #[test]
    fn mixed_content_value_kept() {
        let xml =
            wrap("<Entry><String><Key>Title</Key><Value>ab<x>zz</x>cd</Value></String></Entry>");
        assert_eq!(parse_keepass_xml(&xml).unwrap().items[0].item.title, "abcd");
    }

    #[test]
    fn bad_times_kept_as_text() {
        let xml = wrap(
            "<Entry><Times><CreationTime>nope</CreationTime>\
             <LastModificationTime>never</LastModificationTime></Times>\
             <String><Key>Title</Key><Value>T</Value></String></Entry>",
        );
        let imp = parse_keepass_xml(&xml).unwrap();
        assert_eq!(
            imp.warnings.iter().filter(|w| w.code == "bad_date").count(),
            2
        );
        let extras = imported(&imp.items[0].item);
        assert!(extras.iter().any(|(k, _)| k == "CreationTime"));
        assert!(extras.iter().any(|(k, _)| k == "LastModificationTime"));
    }

    #[test]
    fn duplicate_key_goes_to_extra() {
        let xml = wrap(
            "<Entry><String><Key>Title</Key><Value>first</Value></String>\
             <String><Key>Title</Key><Value>second</Value></String></Entry>",
        );
        let imp = parse_keepass_xml(&xml).unwrap();
        assert_eq!(imp.items[0].item.title, "first");
        let extras = imported(&imp.items[0].item);
        assert!(matches!(extras.iter().find(|(k, _)| k == "Title"),
            Some((_, FieldValue::Text(t))) if t == "second"));
    }

    #[test]
    fn wrong_root_rejected() {
        let err = parse_keepass_xml(b"<Other><Root/></Other>").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidFormat("not a KeePass XML file")
        ));
    }

    #[test]
    fn value_outside_string_ignored() {
        let xml = wrap(
            "<Entry><Value>stray</Value><String><Key>Title</Key><Value>T</Value></String></Entry>",
        );
        let imp = parse_keepass_xml(&xml).unwrap();
        assert_eq!(imp.items[0].item.title, "T");
    }

    #[test]
    fn both_otp_keys_second_to_extra() {
        let xml = wrap(
            "<Entry><String><Key>Title</Key><Value>T</Value></String>\
             <String><Key>UserName</Key><Value>u</Value></String>\
             <String><Key>otp</Key><Value>otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&amp;issuer=Example</Value></String>\
             <String><Key>TimeOtp-Secret-Base32</Key><Value>GEZDGNBVGY3TQOJQ</Value></String></Entry>",
        );
        let imp = parse_keepass_xml(&xml).unwrap();
        let item = &imp.items[0].item;
        assert!(text(item, "totp").contains("JBSWY3DPEHPK3PXP"));
        assert!(imported(item).iter().any(|(k, v)| k == "TimeOtp-Secret-Base32"
            && matches!(v, FieldValue::Concealed(_))));
    }

    #[test]
    fn protected_password_is_password_kind() {
        let imp = parse_keepass_xml(KP).unwrap();
        let item = &by_title(&imp, "Root login").item;
        assert!(matches!(
            item.field("password").map(|f| &f.value),
            Some(FieldValue::Password(_))
        ));
    }
}
