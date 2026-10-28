//! Text of a PDF that lists credentials: a printed password list or a
//! 1Password Emergency Kit.
//!
//! The app extracts the text on the device (PDFKit) and hands it over as
//! UTF-8, pages separated by form feeds; this module never reads PDF bytes
//! and refuses them. The shapes are tried in order:
//! - a 1Password Emergency Kit: the Secret Key, the sign-in address and the
//!   email, found by pattern, become one Login (the account password is
//!   written by hand on the kit, so it is only there when a filled form
//!   field carried it);
//! - a CSV export printed as is: its header line is detected and the
//!   matching CSV parser reads the text from there;
//! - a table whose header row names the columns (cells split by tabs or
//!   by two spaces or more): one Login per row;
//! - labeled records, `Mot de passe : x` or the label alone on a line and
//!   the value on the next: a label already set starts the next record.
//!
//! Records without a URL, username, email, password or one-time code are
//! skipped. Page numbers are dropped.

use crate::error::{Error, Result};
use crate::model::ItemType;

use super::Import;
use super::build::{Draft, host_of};

/// The template slot a label names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Title,
    Url,
    Username,
    Email,
    Password,
    Totp,
    Notes,
}

/// Lower-cased labels, English and French, by slot.
const LABELS: [(Slot, &[&str]); 7] = [
    (
        Slot::Title,
        &[
            "title", "name", "titre", "nom", "item", "account", "compte", "service",
        ],
    ),
    (
        Slot::Url,
        &[
            "url",
            "urls",
            "website",
            "web site",
            "site",
            "site web",
            "site internet",
            "address",
            "web address",
            "adresse",
            "adresse web",
            "login url",
            "sign-in address",
            "link",
            "lien",
        ],
    ),
    (
        Slot::Username,
        &[
            "username",
            "user name",
            "user",
            "user id",
            "login",
            "identifiant",
            "nom d'utilisateur",
            "nom d\u{2019}utilisateur",
            "utilisateur",
        ],
    ),
    (
        Slot::Email,
        &[
            "email",
            "e-mail",
            "email address",
            "e-mail address",
            "courriel",
            "adresse e-mail",
            "adresse email",
        ],
    ),
    (
        Slot::Password,
        &[
            "password",
            "passwd",
            "pwd",
            "pass",
            "mot de passe",
            "mdp",
            "account password",
        ],
    ),
    (
        Slot::Totp,
        &[
            "totp",
            "otp",
            "2fa",
            "one-time password",
            "one-time code",
            "authenticator",
            "code à usage unique",
        ],
    ),
    (
        Slot::Notes,
        &[
            "notes",
            "note",
            "comment",
            "comments",
            "commentaire",
            "commentaires",
            "remarques",
        ],
    ),
];

fn slot_of(label: &str) -> Option<Slot> {
    let label = label.trim().to_lowercase();
    let label = label.split_whitespace().collect::<Vec<_>>().join(" ");
    LABELS
        .iter()
        .find(|(_, names)| names.contains(&label.as_str()))
        .map(|(slot, _)| *slot)
}

/// `label: value` (any colon, a tab also separates), or a bare label whose
/// value is on the next line (`Some((slot, ""))`). `None` for plain text.
fn labeled(line: &str) -> Option<(Slot, &str)> {
    if let Some(slot) = slot_of(line.trim_end_matches([':', '\u{FF1A}'])) {
        return Some((slot, ""));
    }
    let cut = line.find([':', '\u{FF1A}', '\t'])?;
    let (label, rest) = line.split_at(cut);
    let slot = slot_of(label)?;
    let value = rest.get(rest.chars().next().map_or(0, char::len_utf8)..)?;
    Some((slot, value.trim()))
}

/// A line cut before every `label:` it holds. PDFKit often joins lines
/// set close together (`Exemple Atlas Site web : a.fr Identifiant : c`):
/// each label then starts its own piece, and the text before the first
/// one is a piece of its own. A label counts at the start of a word only.
fn pieces(line: &str) -> Vec<&str> {
    let lower = line.to_lowercase();
    if lower.len() != line.len() {
        // Lower-casing moved byte offsets: the line is kept whole.
        return vec![line];
    }
    let colon_after = |end: usize| {
        let rest = lower.get(end..)?;
        let skipped = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        let next = rest.get(skipped..)?.chars().next()?;
        matches!(next, ':' | '\u{FF1A}').then_some(end + skipped + next.len_utf8())
    };
    let mut cuts = Vec::new();
    let mut from = 0usize;
    while from < lower.len() {
        // The earliest label, the longest at one position.
        let found = LABELS
            .iter()
            .flat_map(|(_, names)| names.iter())
            .filter_map(|name| {
                let at = from + lower.get(from..)?.find(name)?;
                let word_start = at == 0
                    || lower
                        .get(..at)
                        .and_then(|b| b.chars().next_back())
                        .is_some_and(char::is_whitespace);
                let colon = colon_after(at + name.len())?;
                word_start.then_some((at, std::cmp::Reverse(name.len()), colon))
            })
            .min();
        let Some((at, _, colon)) = found else { break };
        cuts.push(at);
        from = colon;
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    for cut in cuts.into_iter().chain([line.len()]) {
        if let Some(piece) = line.get(start..cut).map(str::trim)
            && !piece.is_empty()
        {
            out.push(piece);
        }
        start = cut;
    }
    out
}

/// `3`, `3/12`, `Page 3`, `page 3 of 12`, `Page 3 sur 12`.
fn is_page_number(line: &str) -> bool {
    let lower = line.to_lowercase();
    let rest = lower.strip_prefix("page").unwrap_or(&lower);
    let words: Vec<&str> = rest
        .split(|c: char| c.is_whitespace() || c == '/')
        .filter(|w| !w.is_empty() && *w != "of" && *w != "sur")
        .collect();
    (1..=2).contains(&words.len()) && words.iter().all(|w| w.chars().all(|c| c.is_ascii_digit()))
}

/// Bullets or stars only: a password the printout hid.
fn is_masked(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| matches!(c, '•' | '●' | '*' | '·' | '∙') || c.is_whitespace())
}

/// One record being read. Holds secrets: no `Debug`.
#[derive(Default)]
struct Record {
    title: String,
    url: String,
    username: String,
    email: String,
    password: String,
    totp: String,
    notes: Vec<String>,
}

impl Record {
    fn field(&mut self, slot: Slot) -> Option<&mut String> {
        match slot {
            Slot::Title => Some(&mut self.title),
            Slot::Url => Some(&mut self.url),
            Slot::Username => Some(&mut self.username),
            Slot::Email => Some(&mut self.email),
            Slot::Password => Some(&mut self.password),
            Slot::Totp => Some(&mut self.totp),
            Slot::Notes => None,
        }
    }

    fn has(&mut self, slot: Slot) -> bool {
        self.field(slot).is_some_and(|f| !f.is_empty())
    }

    fn set(&mut self, slot: Slot, value: &str) {
        let value = value.trim();
        if value.is_empty() || (slot == Slot::Password && is_masked(value)) {
            return;
        }
        match self.field(slot) {
            Some(f) => value.clone_into(f),
            None => self.notes.push(value.to_owned()),
        }
    }

    /// Holds something a Login is made of.
    fn has_credentials(&self) -> bool {
        [
            &self.url,
            &self.username,
            &self.email,
            &self.password,
            &self.totp,
        ]
        .iter()
        .any(|s| !s.is_empty())
    }

    fn is_empty(&self) -> bool {
        !self.has_credentials() && self.title.is_empty() && self.notes.is_empty()
    }

    /// Appends the record as a Login, or counts it skipped when it holds
    /// no credential. A record with nothing at all is not counted.
    fn finish(self, out: &mut Import) {
        if !self.has_credentials() {
            if !self.is_empty() {
                out.skipped += 1;
            }
            return;
        }
        let entry = u32::try_from(out.items.len()).unwrap_or(u32::MAX);
        let mut d = Draft::new(ItemType::Login);
        let url = with_scheme(&self.url);
        if self.title.is_empty() {
            d.title(host_of(&url).as_deref().unwrap_or(&self.url));
        } else {
            d.title(&self.title);
        }
        d.url(&url);
        if self.username.is_empty() {
            d.set("username", &self.email);
        } else {
            d.set("username", &self.username);
            d.set("email", &self.email);
        }
        d.set("password", &self.password);
        d.set("totp", &self.totp);
        d.notes(&self.notes.join("\n"));
        d.finish(entry, out);
    }
}

/// `example.com/login` read as `https://example.com/login`; anything with
/// a scheme, or blank, is kept.
fn with_scheme(url: &str) -> String {
    let url = url.trim();
    if url.is_empty() || url.contains("://") || !url.contains('.') || url.contains(' ') {
        url.to_owned()
    } else {
        format!("https://{url}")
    }
}

pub(crate) fn parse_pdf_text(bytes: &[u8]) -> Result<Import> {
    if bytes.starts_with(b"%PDF-") {
        return Err(Error::InvalidFormat(
            "PDF: extract its text first (the app does it)",
        ));
    }
    let text = std::str::from_utf8(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes))
        .map_err(|_| Error::InvalidFormat("PDF text is not UTF-8"))?;
    if let Some(kit) = emergency_kit(text) {
        return Ok(kit);
    }
    if let Some(csv) = printed_csv(text)? {
        return Ok(csv);
    }
    let lines: Vec<&str> = text
        .split(['\n', '\r', '\u{000C}'])
        .map(str::trim)
        .filter(|l| !l.is_empty() && !is_page_number(l))
        .collect();
    if let Some(table) = table(&lines) {
        return Ok(table);
    }
    let pieces: Vec<&str> = lines.iter().flat_map(|l| pieces(l)).collect();
    Ok(records(&pieces))
}

/// The CSV parser of the first line, among the first 20, that starts a
/// known CSV export; `None` when there is none or it reads no item.
fn printed_csv(text: &str) -> Result<Option<Import>> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n').take(20) {
        let rest = text.get(offset..).unwrap_or_default();
        offset += line.len();
        if line.trim().is_empty() {
            continue;
        }
        if let Some(format) = super::detect_csv(rest.as_bytes()) {
            let import = super::parse(format, rest.as_bytes())?;
            return Ok((!import.items.is_empty()).then_some(import));
        }
    }
    Ok(None)
}

/// Cells of a table row: split by tabs, or else by runs of two spaces or
/// more.
fn cells(line: &str) -> Vec<&str> {
    let parts: Vec<&str> = if line.contains('\t') {
        line.split('\t').collect()
    } else {
        line.split("  ").collect()
    };
    parts
        .into_iter()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect()
}

/// A table: a header row of two labels or more, one of them username,
/// email or password; then one record per row with as many cells. Rows
/// with another count (titles, footers, wrapped cells) are skipped.
fn table(lines: &[&str]) -> Option<Import> {
    let (at, header) = lines.iter().enumerate().find_map(|(i, l)| {
        let slots: Option<Vec<Slot>> = cells(l).into_iter().map(slot_of).collect();
        let slots = slots.filter(|s| s.len() >= 2)?;
        slots
            .iter()
            .any(|s| matches!(s, Slot::Username | Slot::Email | Slot::Password))
            .then_some((i, slots))
    })?;
    let mut out = Import::default();
    for line in lines.iter().skip(at + 1) {
        let row = cells(line);
        if row.len() != header.len() {
            out.skipped += 1;
            continue;
        }
        let slots: Option<Vec<Slot>> = row.iter().map(|c| slot_of(c)).collect();
        if slots.as_ref() == Some(&header) {
            // The header repeated at the top of a page.
            continue;
        }
        let mut r = Record::default();
        for (slot, value) in header.iter().zip(row) {
            r.set(*slot, value);
        }
        r.finish(&mut out);
    }
    (!out.items.is_empty()).then_some(out)
}

/// Labeled records. A label already set in the current record, or a
/// title, starts the next one. A plain line followed by a label line
/// titles the next record once the current one holds a credential; other
/// plain lines title an empty record or go to the notes.
fn records(lines: &[&str]) -> Import {
    let mut out = Import::default();
    let mut r = Record::default();
    let mut i = 0usize;
    while let Some(line) = lines.get(i) {
        i += 1;
        let next_is_label = lines.get(i).is_some_and(|n| labeled(n).is_some());
        let Some((slot, inline)) = labeled(line) else {
            if r.has_credentials() && next_is_label {
                std::mem::take(&mut r).finish(&mut out);
                r.set(Slot::Title, line);
            } else if !r.has_credentials() && r.notes.is_empty() {
                // A heading above the first record is replaced.
                r.title = (*line).to_owned();
            } else {
                r.notes.push((*line).to_owned());
            }
            continue;
        };
        let mut value = inline;
        if value.is_empty()
            && let Some(next) = lines.get(i)
            && labeled(next).is_none()
        {
            value = next;
            i += 1;
        }
        let starts_next = match slot {
            Slot::Notes => false,
            Slot::Title => !r.is_empty() && (r.has_credentials() || r.has(Slot::Title)),
            s => r.has(s),
        };
        if starts_next {
            std::mem::take(&mut r).finish(&mut out);
        }
        r.set(slot, value);
    }
    r.finish(&mut out);
    out
}

/// A 1Password Secret Key: `A3-` then six groups of five or six capital
/// letters and digits, possibly broken over lines by the extraction.
fn secret_key(text: &str) -> Option<String> {
    text.match_indices("A3-").find_map(|(start, _)| {
        let groups: Vec<&str> = text
            .get(start + 3..)?
            .split(|c: char| c == '-' || c.is_whitespace())
            .filter(|g| !g.is_empty())
            .take(6)
            .collect();
        let well_formed = groups.len() == 6
            && groups.iter().all(|g| {
                (5..=6).contains(&g.len())
                    && g.chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            });
        well_formed.then(|| format!("A3-{}", groups.join("-")))
    })
}

/// A token around `@` with a dot in the domain.
fn email(text: &str) -> Option<&str> {
    text.split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '(' | ')' | ',' | ';'))
        .map(|t| t.trim_matches(|c: char| c == '.' || c == ':'))
        .find(|t| {
            t.split_once('@')
                .is_some_and(|(u, d)| !u.is_empty() && d.contains('.') && !d.starts_with('.'))
        })
}

/// The sign-in address: a `https://` URL, or a `*.1password.*` host.
fn sign_in_address(text: &str) -> Option<&str> {
    text.split_whitespace()
        .map(|t| t.trim_end_matches(['.', ',', ';']))
        .find(|t| {
            let lower = t.to_lowercase();
            lower.starts_with("https://")
                || (!lower.contains('@')
                    && [".1password.com", ".1password.eu", ".1password.ca"]
                        .iter()
                        .any(|s| lower.ends_with(s)))
        })
}

fn emergency_kit(text: &str) -> Option<Import> {
    let key = secret_key(text)?;
    let lower = text.to_lowercase();
    if !lower.contains("1password") && !lower.contains("secret key") {
        return None;
    }
    let mut password = String::new();
    for line in text.lines() {
        if let Some((Slot::Password, v)) = labeled(line.trim())
            && !v.is_empty()
            && !is_masked(v)
        {
            v.clone_into(&mut password);
        }
    }
    let address = sign_in_address(text).unwrap_or("https://my.1password.com");
    let mut d = Draft::new(ItemType::Login);
    d.title("1Password");
    d.url(&with_scheme(address));
    d.set("username", email(text).unwrap_or_default());
    d.set("password", &password);
    d.extra("Secret Key", &key, true);
    let mut out = Import::default();
    d.finish(0, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldValue, Item, validate};

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(FieldValue::Text(s)) => s.clone(),
            Some(FieldValue::Password(s) | FieldValue::Concealed(s) | FieldValue::Otp(s)) => {
                s.to_string()
            }
            _ => String::new(),
        }
    }

    fn imported(item: &Item, label: &str) -> Option<FieldValue> {
        item.sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| &s.fields)
            .find(|f| f.label == label)
            .map(|f| f.value.clone())
    }

    fn parse(s: &str) -> Import {
        let imp = parse_pdf_text(s.as_bytes()).unwrap();
        for it in &imp.items {
            validate(&it.item).unwrap();
        }
        imp
    }

    #[test]
    fn raw_pdf_bytes_are_refused() {
        assert!(parse_pdf_text(b"%PDF-1.7\n%\xE2\xE3").is_err());
        assert!(parse_pdf_text(b"\xFF\xFE not utf8").is_err());
    }

    #[test]
    fn labeled_records_inline_and_on_next_line() {
        let imp = parse(
            "My passwords\n\
             Example Mail\n\
             Website: mail.example.com\n\
             Username: alice@example.com\n\
             Password: Invented-Pass-1\n\
             Notes: main mailbox\n\
             \u{000C}Page 1 of 2\n\
             Shop\n\
             URL\n\
             https://shop.example.net/login\n\
             Mot de passe :\n\
             Second-Invented-2\n\
             Identifiant : bob\n\
             2\n",
        );
        assert_eq!(imp.items.len(), 2);
        let a = &imp.items[0].item;
        assert_eq!(a.item_type, ItemType::Login);
        assert_eq!(a.title, "Example Mail");
        assert_eq!(a.urls[0].url, "https://mail.example.com");
        assert_eq!(text(a, "username"), "alice@example.com");
        assert_eq!(text(a, "password"), "Invented-Pass-1");
        assert_eq!(a.notes, "main mailbox");
        let b = &imp.items[1].item;
        assert_eq!(b.title, "Shop");
        assert_eq!(b.urls[0].url, "https://shop.example.net/login");
        assert_eq!(text(b, "username"), "bob");
        assert_eq!(text(b, "password"), "Second-Invented-2");
        assert!(b.notes.is_empty(), "page numbers are dropped");
    }

    #[test]
    fn repeated_label_starts_next_record_and_title_falls_back_to_host() {
        let imp = parse(
            "Username: u1\nPassword: p1\nURL: https://one.example.com\n\
             Username: u2\nPassword: p2\nURL: two.example.org\n",
        );
        assert_eq!(imp.items.len(), 2);
        assert_eq!(imp.items[0].item.title, "one.example.com");
        assert_eq!(imp.items[1].item.title, "two.example.org");
        assert_eq!(text(&imp.items[1].item, "password"), "p2");
    }

    #[test]
    fn email_only_becomes_username_and_masked_password_is_dropped() {
        let imp = parse("Title: Bank\nEmail: carol@example.com\nPassword: ••••••••\n");
        let it = &imp.items[0].item;
        assert_eq!(text(it, "username"), "carol@example.com");
        assert!(text(it, "password").is_empty());
    }

    #[test]
    fn without_username_it_is_a_password_item() {
        let imp = parse("Title: Router admin\nPassword: Invented-3\n");
        assert_eq!(imp.items[0].item.item_type, ItemType::Password);
        assert!(imp.warnings.iter().any(|w| w.code == "login_to_password"));
    }

    #[test]
    fn records_without_credentials_are_skipped() {
        let imp = parse("Title: Shopping list\nNotes: eggs\nTitle: Other\nNotes: milk\n");
        assert!(imp.items.is_empty());
        assert_eq!(imp.skipped, 2);
    }

    #[test]
    fn table_with_header_row() {
        let imp = parse(
            "Exported passwords\n\
             Name\tURL\tUsername\tPassword\n\
             Forum\thttps://forum.example.com\tdave\tInvented-4\n\
             Wiki  wiki.example.org  erin  Invented 5\n\
             a wrapped line\n\
             Page 1\n\
             Name\tURL\tUsername\tPassword\n",
        );
        assert_eq!(imp.items.len(), 2);
        assert_eq!(imp.skipped, 1);
        let b = &imp.items[1].item;
        assert_eq!(b.title, "Wiki");
        assert_eq!(b.urls[0].url, "https://wiki.example.org");
        assert_eq!(text(b, "username"), "erin");
        assert_eq!(text(b, "password"), "Invented 5");
    }

    #[test]
    fn printed_csv_is_read_by_its_parser() {
        let imp = parse(
            "Passwords\n\nname,url,username,password\nA,https://a.example.com,u,Invented-6\n",
        );
        assert_eq!(imp.items.len(), 1);
        assert_eq!(text(&imp.items[0].item, "password"), "Invented-6");
    }

    #[test]
    fn totp_secret_is_kept() {
        let imp = parse("Title: Git\nUsername: frank\nOTP: JBSWY3DPEHPK3PXP\n");
        let it = &imp.items[0].item;
        assert!(text(it, "totp").starts_with("otpauth://"));
    }

    #[test]
    fn emergency_kit_becomes_one_login() {
        let imp = parse(
            "1Password\nEmergency Kit\nCreated for Grace on October 1, 2026.\n\
             SIGN-IN ADDRESS\nhttps://my.1password.eu\n\
             EMAIL ADDRESS\ngrace@example.com\n\
             SECRET KEY\nA3-ABC123-DEF456-GHJ78\nKLM90-NPQ12-RST34\n\
             ACCOUNT PASSWORD\n",
        );
        assert_eq!(imp.items.len(), 1);
        let it = &imp.items[0].item;
        assert_eq!(it.item_type, ItemType::Login);
        assert_eq!(it.title, "1Password");
        assert_eq!(it.urls[0].url, "https://my.1password.eu");
        assert_eq!(text(it, "username"), "grace@example.com");
        assert!(text(it, "password").is_empty());
        assert!(matches!(
            imported(it, "Secret Key"),
            Some(FieldValue::Concealed(k)) if k.as_str() == "A3-ABC123-DEF456-GHJ78-KLM90-NPQ12-RST34"
        ));
    }

    #[test]
    fn emergency_kit_with_filled_password_field() {
        let imp = parse(
            "Secret Key A3-ABC123-DEF456-GHJ78-KLM90-NPQ12-RST34\n\
             team.1password.com\nheidi@example.com\nPassword: Invented-7\n",
        );
        let it = &imp.items[0].item;
        assert_eq!(it.urls[0].url, "https://team.1password.com");
        assert_eq!(text(it, "password"), "Invented-7");
    }

    #[test]
    fn labels_joined_on_one_line_by_pdfkit() {
        // What PDFKit returns for a printout set with tight line spacing.
        let imp = parse(
            "Mots de passe imprimés (valeurs fictives)\n\
             Exemple Atlas Site web : atlas.exemple.fr Identifiant : camille.durand@exemple.fr Mot de passe : motdepasse-fictif-1\n\
             Exemple Borée Site web : https://boree.exemple.fr/connexion Identifiant : camille\n\
             Mot de passe : motdepasse-fictif-2 Notes : compte famille\n\
             Routeur du salon\n\
             Mot de passe : motdepasse-fictif-3\n",
        );
        assert_eq!(imp.items.len(), 3);
        let a = &imp.items[0].item;
        assert_eq!(a.title, "Exemple Atlas");
        assert_eq!(a.urls[0].url, "https://atlas.exemple.fr");
        assert_eq!(text(a, "username"), "camille.durand@exemple.fr");
        assert_eq!(text(a, "password"), "motdepasse-fictif-1");
        let b = &imp.items[1].item;
        assert_eq!(b.title, "Exemple Borée");
        assert_eq!(text(b, "password"), "motdepasse-fictif-2");
        assert_eq!(b.notes, "compte famille");
        let c = &imp.items[2].item;
        assert_eq!(c.title, "Routeur du salon");
        assert_eq!(c.item_type, ItemType::Password);
    }

    #[test]
    fn pieces_cut_at_word_start_labels_only() {
        assert_eq!(
            pieces("Shop URL: https://a.example Password: x"),
            vec!["Shop", "URL: https://a.example", "Password: x"]
        );
        // `pass` inside a word, and a label without a colon, do not cut.
        assert_eq!(
            pieces("Motdepass: x and user y"),
            vec!["Motdepass: x and user y"]
        );
        assert_eq!(pieces("Email address: a@b.c"), vec!["Email address: a@b.c"]);
    }

    #[test]
    fn page_numbers() {
        for l in ["3", "3/12", "Page 3", "page 3 of 12", "Page 3 sur 12"] {
            assert!(is_page_number(l), "{l}");
        }
        for l in ["Page", "Paris 75001 France", "2026 Mail 3", "1 2 3"] {
            assert!(!is_page_number(l), "{l}");
        }
    }
}
