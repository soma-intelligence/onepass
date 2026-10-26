//! Shared PSL vectors: the extension (tldts) and the bridge (psl crate) must
//! agree on what "same site" means.

use onepass_bridge::origin::Origin;
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    a: String,
    b: String,
    same_site: bool,
    site_a: String,
}

#[derive(Deserialize)]
struct File {
    cases: Vec<Case>,
}

#[test]
fn psl_vectors_match_extension() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../extension/test/vectors/psl.json"
    );
    let raw = std::fs::read_to_string(path).expect("psl.json readable");
    let file: File = serde_json::from_str(&raw).expect("psl.json valid");
    assert!(!file.cases.is_empty());
    for c in &file.cases {
        let a = Origin::parse(&c.a).unwrap_or_else(|e| panic!("parse {}: {e:?}", c.a));
        let b = Origin::parse(&c.b).unwrap_or_else(|e| panic!("parse {}: {e:?}", c.b));
        assert_eq!(a.site(), c.site_a, "site of {}", c.a);
        assert_eq!(a.site() == b.site(), c.same_site, "{} vs {}", c.a, c.b);
    }
}
