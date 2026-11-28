//! Machine readable zone of a TD3 travel document (a passport): two lines
//! of 44 characters, ICAO 9303 part 4.

use std::fmt;

use zeroize::Zeroize;

/// Why a MRZ was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrzError {
    /// Not two lines of 44 characters.
    Length,
    /// A check digit does not agree; names the field.
    CheckDigit(&'static str),
    /// A character outside `A-Z`, `0-9` and `<`.
    Charset,
}

impl fmt::Display for MrzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MrzError::Length => f.write_str("MRZ must be two lines of 44 characters"),
            MrzError::CheckDigit(field) => write!(f, "MRZ check digit mismatch: {field}"),
            MrzError::Charset => f.write_str("MRZ has a character outside A-Z, 0-9 and <"),
        }
    }
}

impl std::error::Error for MrzError {}

/// A parsed TD3 MRZ. Fields are the printed values, filler `<` removed.
/// The content identifies a person: `Debug` hides it and the strings are
/// wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Mrz {
    pub document_code: String,
    pub issuing_state: String,
    pub surname: String,
    pub given_names: String,
    pub document_number: String,
    pub nationality: String,
    /// YYMMDD.
    pub birth_date: String,
    pub sex: char,
    /// YYMMDD.
    pub expiry_date: String,
    pub optional_data: String,
    /// The two lines after OCR correction, joined by a newline.
    pub raw: String,
}

impl fmt::Debug for Mrz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Mrz(..)")
    }
}

impl Drop for Mrz {
    fn drop(&mut self) {
        self.document_code.zeroize();
        self.issuing_state.zeroize();
        self.surname.zeroize();
        self.given_names.zeroize();
        self.document_number.zeroize();
        self.nationality.zeroize();
        self.birth_date.zeroize();
        self.expiry_date.zeroize();
        self.optional_data.zeroize();
        self.raw.zeroize();
    }
}

impl Mrz {
    /// Document number, birth date and expiry date, each followed by its
    /// check digit (ICAO 9303-11, 4.3): the input of the BAC key seed hash.
    /// The number is padded with `<` to 9 characters.
    pub fn bac_key_seed_input(&self) -> String {
        let number = format!("{:<<9}", self.document_number);
        let mut out = String::with_capacity(24);
        for field in [number.as_str(), &self.birth_date, &self.expiry_date] {
            out.push_str(field);
            out.push(char::from(b'0' + check_digit(field)));
        }
        out
    }
}

fn char_value(c: u8) -> u32 {
    match c {
        b'0'..=b'9' => u32::from(c - b'0'),
        b'A'..=b'Z' => u32::from(c - b'A') + 10,
        _ => 0, // `<` and anything else
    }
}

/// ICAO 9303 check digit: weights 7, 3, 1 repeating, `<` is 0, `A` is 10.
pub fn check_digit(s: &str) -> u8 {
    const W: [u32; 3] = [7, 3, 1];
    let sum: u32 = s
        .bytes()
        .enumerate()
        .map(|(i, c)| char_value(c) * W[i % 3])
        .sum();
    (sum % 10) as u8
}

/// Whether `digit` (a MRZ character) is the check digit of `field`.
fn digit_ok(field: &[u8], digit: u8) -> bool {
    let s = std::str::from_utf8(field).unwrap_or("");
    digit == b'0' + check_digit(s)
}

/// Letters an OCR reads in place of a digit.
fn ocr_digit(c: u8) -> u8 {
    match c {
        b'O' => b'0',
        b'I' => b'1',
        b'B' => b'8',
        b'S' => b'5',
        b'Z' => b'2',
        other => other,
    }
}

/// Validates a numeric field against its check digit, undoing OCR letter
/// for digit confusions when (and only when) the digit then agrees. The
/// field and the digit are corrected in place.
fn fix_numeric(
    line: &mut [u8; 44],
    field: std::ops::Range<usize>,
    digit_at: usize,
    name: &'static str,
) -> Result<(), MrzError> {
    if digit_ok(&line[field.clone()], line[digit_at]) {
        return Ok(());
    }
    let mut fixed = *line;
    for i in field.clone().chain(std::iter::once(digit_at)) {
        fixed[i] = ocr_digit(fixed[i]);
    }
    let all_digits = field
        .clone()
        .chain(std::iter::once(digit_at))
        .all(|i| fixed[i].is_ascii_digit());
    if all_digits && digit_ok(&fixed[field], fixed[digit_at]) {
        *line = fixed;
        Ok(())
    } else {
        Err(MrzError::CheckDigit(name))
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A name field: `<` is a space, trailing filler dropped.
fn name_text(b: &[u8]) -> String {
    text(b).trim_end_matches('<').replace('<', " ")
}

/// Parses and validates a TD3 MRZ given as its two lines.
pub fn parse_td3(lines: &[&str]) -> Result<Mrz, MrzError> {
    if lines.len() != 2 || lines.iter().any(|l| l.len() != 44) {
        return Err(MrzError::Length);
    }
    let valid = |c: &u8| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'<';
    if !lines.iter().all(|l| l.bytes().all(|c| valid(&c))) {
        return Err(MrzError::Charset);
    }
    let l1: [u8; 44] = lines[0]
        .as_bytes()
        .try_into()
        .map_err(|_| MrzError::Length)?;
    let mut l2: [u8; 44] = lines[1]
        .as_bytes()
        .try_into()
        .map_err(|_| MrzError::Length)?;

    // Document number is alphanumeric: no OCR fix.
    if !digit_ok(&l2[0..9], l2[9]) {
        return Err(MrzError::CheckDigit("document_number"));
    }
    fix_numeric(&mut l2, 13..19, 19, "birth_date")?;
    fix_numeric(&mut l2, 21..27, 27, "expiry_date")?;
    let optional_empty = l2[28..42].iter().all(|&c| c == b'<');
    let optional_ok = digit_ok(&l2[28..42], l2[42]) || (optional_empty && l2[42] == b'<');
    if !optional_ok {
        return Err(MrzError::CheckDigit("optional_data"));
    }
    let mut composite = Vec::with_capacity(39);
    composite.extend_from_slice(&l2[0..10]);
    composite.extend_from_slice(&l2[13..20]);
    composite.extend_from_slice(&l2[21..43]);
    if !digit_ok(&composite, l2[43]) {
        return Err(MrzError::CheckDigit("composite"));
    }

    let names = std::str::from_utf8(&l1[5..44]).map_err(|_| MrzError::Charset)?;
    let (surname, given) = match names.split_once("<<") {
        Some((s, g)) => (s, g),
        None => (names, ""),
    };
    let sex = match l2[20] {
        b'<' => ' ',
        c => char::from(c),
    };
    let raw = format!("{}\n{}", lines[0], text(&l2));
    Ok(Mrz {
        document_code: text(&l1[0..2]).trim_end_matches('<').to_string(),
        issuing_state: text(&l1[2..5]).trim_end_matches('<').to_string(),
        surname: name_text(surname.as_bytes()),
        given_names: name_text(given.as_bytes()),
        document_number: text(&l2[0..9]).trim_end_matches('<').to_string(),
        nationality: text(&l2[10..13]).trim_end_matches('<').to_string(),
        birth_date: text(&l2[13..19]),
        sex,
        expiry_date: text(&l2[21..27]),
        optional_data: text(&l2[28..42]).trim_end_matches('<').to_string(),
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const L1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    const L2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    #[test]
    fn mrz_parses_icao_specimen() {
        let m = parse_td3(&[L1, L2]).unwrap();
        assert_eq!(m.document_code, "P");
        assert_eq!(m.issuing_state, "UTO");
        assert_eq!(m.surname, "ERIKSSON");
        assert_eq!(m.given_names, "ANNA MARIA");
        assert_eq!(m.document_number, "L898902C3");
        assert_eq!(m.nationality, "UTO");
        assert_eq!(m.birth_date, "740812");
        assert_eq!(m.sex, 'F');
        assert_eq!(m.expiry_date, "120415");
        assert_eq!(m.optional_data, "ZE184226B");
        assert_eq!(m.bac_key_seed_input(), "L898902C3674081221204159");
    }

    #[test]
    fn mrz_rejects_bad_check_digit() {
        let l2 = L2.replacen("L898902C36", "L898902C35", 1);
        assert_eq!(
            parse_td3(&[L1, &l2]).unwrap_err(),
            MrzError::CheckDigit("document_number")
        );
    }

    #[test]
    fn mrz_fixes_ocr_confusion_when_check_digit_agrees() {
        let l2 = L2.replacen("740812", "74O812", 1);
        let m = parse_td3(&[L1, &l2]).unwrap();
        assert_eq!(m.birth_date, "740812");
        // The corrected lines are what `raw` keeps.
        assert!(m.raw.contains("7408122F"));
    }

    #[test]
    fn mrz_rejects_unfixable() {
        // Letters are legitimate in a document number: no OCR fix applies,
        // and the check digit no longer agrees.
        let l2 = L2.replacen("L898902C3", "L8989O2C3", 1);
        assert_eq!(
            parse_td3(&[L1, &l2]).unwrap_err(),
            MrzError::CheckDigit("document_number")
        );
        // A numeric field whose fix does not agree with its digit either.
        let l2 = L2.replacen("740812", "74O813", 1);
        assert!(parse_td3(&[L1, &l2]).is_err());
    }

    #[test]
    fn mrz_rejects_wrong_length() {
        let long = format!("{L1}<");
        assert_eq!(parse_td3(&[&long, L2]).unwrap_err(), MrzError::Length);
        assert_eq!(parse_td3(&[L1]).unwrap_err(), MrzError::Length);
    }

    #[test]
    fn mrz_rejects_bad_charset() {
        let l1 = L1.replacen("ERIKSSON", "eriksson", 1);
        assert_eq!(parse_td3(&[&l1, L2]).unwrap_err(), MrzError::Charset);
    }

    #[test]
    fn mrz_rejects_bad_composite() {
        // Same field digits, wrong composite digit.
        let l2 = format!("{}1", &L2[..43]);
        assert_eq!(
            parse_td3(&[L1, &l2]).unwrap_err(),
            MrzError::CheckDigit("composite")
        );
    }

    #[test]
    fn check_digit_known_values() {
        assert_eq!(check_digit("520727"), 3);
        assert_eq!(check_digit("L898902C3"), 6);
        assert_eq!(check_digit("<<<"), 0);
    }

    #[test]
    fn debug_hides_content() {
        let m = parse_td3(&[L1, L2]).unwrap();
        assert!(!format!("{m:?}").contains("ERIKSSON"));
    }
}
