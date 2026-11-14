//! Organization types, fingerprint words and the join link format.

use onepass_ffi::{
    FfiOrgInvite, OnePassError, org_fingerprint_words, org_invite_encode, org_invite_parse,
    org_parse_dns_txt, org_parse_fingerprint,
};

const SERVER: &str = "https://mailbox.example.com/functions/v1/mailbox";
const LOOPBACK: &str = "http://127.0.0.1:54321/functions/v1/mailbox";

fn sample_invite() -> FfiOrgInvite {
    FfiOrgInvite {
        server_url: SERVER.into(),
        mailbox_id: "0a".repeat(16),
        org_id: "0b".repeat(16),
        account_id: "0c".repeat(16),
        fingerprint: vec![9u8; 32],
        nonce: vec![0xd1; 32],
        credential_seed: vec![0xe2; 32],
        member_token: vec![0xf3; 32],
        domain: Some("example.com".into()),
    }
}

/// The valid link with one query pair replaced (`None` drops it); a value
/// is spliced verbatim, so callers pass it already percent-encoded.
fn link_with(key: &str, value: Option<&str>) -> String {
    let link = org_invite_encode(sample_invite()).unwrap();
    let (base, query) = link.split_once('?').unwrap();
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|p| !p.starts_with(&format!("{key}=")))
        .map(str::to_owned)
        .collect();
    if let Some(v) = value {
        pairs.push(format!("{key}={v}"));
    }
    format!("{base}?{}", pairs.join("&"))
}

fn parse_with(key: &str, value: &str) -> Result<FfiOrgInvite, OnePassError> {
    org_invite_parse(link_with(key, Some(value)), false)
}

fn refused(r: Result<FfiOrgInvite, OnePassError>) -> bool {
    matches!(r, Err(OnePassError::InvalidInput { .. }))
}

#[test]
fn fingerprint_words_are_four_groups_of_five() {
    let w = org_fingerprint_words(vec![7u8; 32]).unwrap();
    assert_eq!(w.len(), 4);
    assert!(w.iter().all(|g| g.len() == 5));
}

#[test]
fn fingerprint_words_ignore_locale() {
    let w = org_fingerprint_words(vec![7u8; 32]).unwrap();
    assert_eq!(w, org_fingerprint_words(vec![7u8; 32]).unwrap());
    assert!(w.concat().iter().all(|w| w.is_ascii()));
    assert_ne!(w, org_fingerprint_words(vec![8u8; 32]).unwrap());
}

#[test]
fn fingerprint_words_refuse_wrong_length() {
    assert!(org_fingerprint_words(vec![0; 31]).is_err());
    assert!(org_fingerprint_words(vec![0; 33]).is_err());
}

#[test]
fn dns_and_mdm_texts_parse_to_the_same_fingerprint() {
    let fpr = [9u8; 32];
    let text = onepass_core::org::fingerprint_base32(&fpr);
    assert_eq!(
        org_parse_dns_txt(format!("v=op1; org={text}")).unwrap(),
        fpr
    );
    assert_eq!(org_parse_fingerprint(text.clone()).unwrap(), fpr);
    assert_eq!(org_parse_fingerprint(text.to_lowercase()).unwrap(), fpr);
    assert!(org_parse_fingerprint(text[1..].into()).is_err());
    assert!(org_parse_fingerprint(format!("{}1", &text[1..])).is_err());
}

#[test]
fn invite_round_trips() {
    let i = sample_invite();
    assert_eq!(
        org_invite_parse(org_invite_encode(i.clone()).unwrap(), false).unwrap(),
        i
    );
    let no_domain = FfiOrgInvite { domain: None, ..i };
    assert_eq!(
        org_invite_parse(org_invite_encode(no_domain.clone()).unwrap(), false).unwrap(),
        no_domain
    );
}

#[test]
fn invite_parse_refuses_http_server() {
    assert!(matches!(
        parse_with("s", "http%3A%2F%2Fa.example"),
        Err(OnePassError::InvalidInput { .. })
    ));
}

#[test]
fn invite_parse_refuses_missing_duplicate_and_unknown_keys() {
    for k in ["s", "m", "o", "a", "f", "n", "c", "t", "v"] {
        assert!(
            refused(org_invite_parse(link_with(k, None), false)),
            "missing {k}"
        );
    }
    let link = org_invite_encode(sample_invite()).unwrap();
    for k in ["m", "n", "t", "a", "d"] {
        let dup = format!("{link}&{k}=00");
        assert!(refused(org_invite_parse(dup, false)), "repeated {k}");
    }
    assert!(refused(org_invite_parse(format!("{link}&x=1"), false)));
}

#[test]
fn invite_parse_refuses_bad_lengths() {
    assert!(refused(parse_with("m", &"0a".repeat(15))));
    assert!(refused(parse_with("o", &"0b".repeat(17))));
    assert!(refused(parse_with("a", &"0c".repeat(15))));
    assert!(refused(parse_with("n", &"d1".repeat(16))));
    assert!(refused(parse_with("n", &"d1".repeat(33))));
    assert!(refused(parse_with("c", &"e2".repeat(31))));
    assert!(refused(parse_with("t", &"f3".repeat(31))));
    assert!(refused(parse_with("f", "NOTBASE32")));
    // Uppercase hex is refused: one spelling per link.
    assert!(refused(parse_with("m", &"0A".repeat(16))));
}

#[test]
fn invite_parse_refuses_other_scheme_host_or_version() {
    let link = org_invite_encode(sample_invite()).unwrap();
    let query = link.split_once('?').unwrap().1;
    for base in [
        "https://org/join",
        "onepass://item/join",
        "onepass://org/other",
        "onepass://org/join/",
        "onepass://org:1/join",
        "onepass://u@org/join",
    ] {
        assert!(refused(org_invite_parse(format!("{base}?{query}"), false)));
    }
    assert!(refused(org_invite_parse(format!("{link}#x"), false)));
    assert!(refused(parse_with("v", "2")));
}

#[test]
fn invite_parse_refuses_oversized_link() {
    let link = org_invite_encode(sample_invite()).unwrap();
    let big = format!("{link}&x={}", "a".repeat(2049 - link.len() - 3));
    assert_eq!(big.len(), 2049);
    assert!(refused(org_invite_parse(big, false)));
}

#[test]
fn invite_parse_refuses_bad_domain() {
    for d in [
        "Example.com",
        "example.com.",
        "a..b",
        "nodot",
        "-a.example.com",
        "a_b.example.com",
        &format!("{}.com", "a".repeat(64)),
        &format!("{}.com", vec!["a".repeat(60); 5].join(".")),
    ] {
        assert!(refused(parse_with("d", d)), "{d}");
    }
    assert!(parse_with("d", "sub.example-1.co").is_ok());
}

#[test]
fn loopback_http_only_when_allowed() {
    let enc = LOOPBACK.replace(':', "%3A").replace('/', "%2F");
    let link = link_with("s", Some(&enc));
    let got = org_invite_parse(link.clone(), true).unwrap();
    assert_eq!(got.server_url, LOOPBACK);
    assert!(refused(org_invite_parse(link, false)));
    // Only that exact URL.
    let other = "http%3A%2F%2F127.0.0.1%3A54322%2Ffunctions%2Fv1%2Fmailbox";
    assert!(refused(org_invite_parse(link_with("s", Some(other)), true)));
}
