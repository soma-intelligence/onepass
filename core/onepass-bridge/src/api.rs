//! Application messages carried in the clear text of a `msg` frame
//! (spec 6.7 and 7.2).
//!
//! A request is `{"id": n, "op": "...", ...}`. A reply is
//! `{"id": n, "ok": {...}}` or `{"id": n, "err": {"code", "msg"}}`.
//! Requests reject unknown fields. Secret strings, in requests and in
//! replies, are `SecretString`: wiped on drop, masked in `Debug`.

use std::fmt;

use onepass_core::model::MatchRule;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::AppErrorCode;
use crate::origin::MatchQuality;
use crate::provider::ProviderId;

/// A secret string: wiped on drop, `**` in `Debug`, a plain JSON string
/// on the wire.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(pub Zeroizing<String>);

impl SecretString {
    pub fn new(s: Zeroizing<String>) -> Self {
        Self(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(Zeroizing::new(s.to_owned()))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("**")
    }
}

/// Where the action comes from in the extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ctx {
    Popup,
    Menu,
    Overlay,
    SavePrompt,
    Chain,
}

impl Ctx {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Popup => "popup",
            Self::Menu => "menu",
            Self::Overlay => "overlay",
            Self::SavePrompt => "save_prompt",
            Self::Chain => "chain",
        }
    }
}

/// A login field the extension may ask to fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillField {
    Username,
    Password,
    Totp,
}

/// Kind of `list_fillable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillKind {
    Card,
    Identity,
}

/// Match rule of a saved login, as on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    Domain,
    ExactHost,
    ExactUrl,
    Never,
}

impl From<Rule> for MatchRule {
    fn from(r: Rule) -> MatchRule {
        match r {
            Rule::Domain => MatchRule::Domain,
            Rule::ExactHost => MatchRule::ExactHost,
            Rule::ExactUrl => MatchRule::ExactUrl,
            Rule::Never => MatchRule::Never,
        }
    }
}

/// Generator recipe kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeKind {
    Random,
    Memorable,
    Pin,
    Smart,
}

/// Generator request. `length` and `symbols` may be left out: each kind
/// has its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub kind: RecipeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbols: Option<bool>,
}

/// An application request. Every operation carries the request `id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status {
        id: u64,
    },
    Unlock {
        id: u64,
    },
    Vaults {
        id: u64,
    },
    ListForOrigin {
        id: u64,
        ctx: Ctx,
        origin: String,
    },
    Search {
        id: u64,
        ctx: Ctx,
        query: String,
    },
    ListFillable {
        id: u64,
        ctx: Ctx,
        origin: String,
        kind: FillKind,
    },
    FillLogin {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
        fields: Vec<FillField>,
    },
    FillCard {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
    },
    FillIdentity {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
    },
    Totp {
        id: u64,
        ctx: Ctx,
        item_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<String>,
    },
    Reveal {
        id: u64,
        ctx: Ctx,
        item_id: String,
        field: String,
    },
    CheckCredentials {
        id: u64,
        ctx: Ctx,
        origin: String,
        username: String,
        password: SecretString,
    },
    SaveLogin {
        id: u64,
        ctx: Ctx,
        origin: String,
        title: String,
        username: String,
        password: SecretString,
        vault_id: String,
        rule: Rule,
        tags: Vec<String>,
    },
    UpdatePassword {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
        password: SecretString,
    },
    Generate {
        id: u64,
        ctx: Ctx,
        recipe: Recipe,
    },
    ProviderAccounts {
        id: u64,
        ctx: Ctx,
        provider: ProviderId,
        origin: String,
    },
    FillProvider {
        id: u64,
        ctx: Ctx,
        account_item_id: String,
        provider: ProviderId,
        provider_origin: String,
        site_origin: String,
        fields: Vec<FillField>,
    },
    LinkProvider {
        id: u64,
        ctx: Ctx,
        site_origin: String,
        provider: ProviderId,
        account_item_id: String,
    },
}

impl Request {
    /// The request id.
    pub fn id(&self) -> u64 {
        match self {
            Self::Status { id }
            | Self::Unlock { id }
            | Self::Vaults { id }
            | Self::ListForOrigin { id, .. }
            | Self::Search { id, .. }
            | Self::ListFillable { id, .. }
            | Self::FillLogin { id, .. }
            | Self::FillCard { id, .. }
            | Self::FillIdentity { id, .. }
            | Self::Totp { id, .. }
            | Self::Reveal { id, .. }
            | Self::CheckCredentials { id, .. }
            | Self::SaveLogin { id, .. }
            | Self::UpdatePassword { id, .. }
            | Self::Generate { id, .. }
            | Self::ProviderAccounts { id, .. }
            | Self::FillProvider { id, .. }
            | Self::LinkProvider { id, .. } => *id,
        }
    }

    /// The wire name of the operation.
    pub fn op(&self) -> &'static str {
        match self {
            Self::Status { .. } => "status",
            Self::Unlock { .. } => "unlock",
            Self::Vaults { .. } => "vaults",
            Self::ListForOrigin { .. } => "list_for_origin",
            Self::Search { .. } => "search",
            Self::ListFillable { .. } => "list_fillable",
            Self::FillLogin { .. } => "fill_login",
            Self::FillCard { .. } => "fill_card",
            Self::FillIdentity { .. } => "fill_identity",
            Self::Totp { .. } => "totp",
            Self::Reveal { .. } => "reveal",
            Self::CheckCredentials { .. } => "check_credentials",
            Self::SaveLogin { .. } => "save_login",
            Self::UpdatePassword { .. } => "update_password",
            Self::Generate { .. } => "generate",
            Self::ProviderAccounts { .. } => "provider_accounts",
            Self::FillProvider { .. } => "fill_provider",
            Self::LinkProvider { .. } => "link_provider",
        }
    }
}

/// Kind of a summarized item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryKind {
    Login,
    Card,
    Identity,
}

/// A sign-in method of a summarized login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Method {
    pub provider: ProviderId,
    pub account_email: String,
}

/// What the extension may see of an item without a secret (spec 7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub item_id: String,
    pub vault_id: String,
    pub vault_name: String,
    pub title: String,
    pub subtitle: String,
    pub kind: SummaryKind,
    pub icon_letter: String,
    pub icon_color: String,
    pub has_password: bool,
    pub has_totp: bool,
    pub methods: Vec<Method>,
    #[serde(rename = "match")]
    pub match_quality: Option<MatchQuality>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
}

/// Address of `fill_identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressOut {
    pub line1: String,
    pub line2: String,
    pub city: String,
    pub postal_code: String,
    pub region: String,
    pub country: String,
}

/// `check_credentials` verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    New,
    Same,
    Update,
}

/// The `ok` payload of a reply, one shape per operation.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Response {
    Status {
        locked: bool,
        account: String,
        vaults: usize,
    },
    Unlock {
        locked: bool,
    },
    Vaults {
        vaults: Vec<VaultEntry>,
    },
    Items {
        items: Vec<Summary>,
    },
    /// `fill_login` and `fill_provider`.
    Login {
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<SecretString>,
        #[serde(skip_serializing_if = "Option::is_none")]
        totp: Option<SecretString>,
    },
    /// Month `MM` and year `YYYY`, empty when unknown.
    Card {
        cardholder: String,
        number: SecretString,
        exp_month: String,
        exp_year: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cvv: Option<SecretString>,
    },
    Identity {
        #[serde(skip_serializing_if = "Option::is_none")]
        given_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        family_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tel: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        organization: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        birthday: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<AddressOut>,
    },
    Totp {
        code: SecretString,
        remaining: u32,
    },
    Reveal {
        value: SecretString,
    },
    CheckCredentials {
        status: CredentialStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        item_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
    ItemId {
        item_id: String,
    },
    Generate {
        password: SecretString,
        entropy_bits: f64,
    },
    ProviderAccounts {
        accounts: Vec<Summary>,
        #[serde(skip_serializing_if = "Option::is_none")]
        linked_item_id: Option<String>,
    },
    /// `{}`.
    Empty {},
}

/// Body of an error reply. `msg` never holds a secret nor user data
/// beyond an item id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub msg: String,
}

impl ErrorBody {
    pub fn new(code: AppErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code: code.as_str(),
            msg: msg.into(),
        }
    }
}

/// A reply envelope.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Reply {
    Ok { id: u64, ok: Box<Response> },
    Err { id: Option<u64>, err: ErrorBody },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// Parses the wire string, checks the id and op, and checks that
    /// serializing gives back the same JSON value.
    fn round_trip(wire: &str, id: u64, op: &str) -> Request {
        let req: Request = serde_json::from_str(wire).unwrap();
        assert_eq!(req.id(), id);
        assert_eq!(req.op(), op);
        let back: Value = serde_json::to_value(&req).unwrap();
        let orig: Value = serde_json::from_str(wire).unwrap();
        assert_eq!(back, orig);
        req
    }

    #[test]
    fn request_json_round_trip_status() {
        round_trip(r#"{"id":1,"op":"status"}"#, 1, "status");
    }

    #[test]
    fn request_json_round_trip_unlock() {
        round_trip(r#"{"id":2,"op":"unlock"}"#, 2, "unlock");
    }

    #[test]
    fn request_json_round_trip_vaults() {
        round_trip(r#"{"op":"vaults","id":3}"#, 3, "vaults");
    }

    #[test]
    fn request_json_round_trip_list_for_origin() {
        let r = round_trip(
            r#"{"id":4,"op":"list_for_origin","ctx":"menu","origin":"https://atlas-cloud.test"}"#,
            4,
            "list_for_origin",
        );
        assert!(matches!(r, Request::ListForOrigin { ctx: Ctx::Menu, .. }));
    }

    #[test]
    fn request_json_round_trip_search() {
        round_trip(
            r#"{"id":5,"op":"search","ctx":"popup","query":"atlas"}"#,
            5,
            "search",
        );
    }

    #[test]
    fn request_json_round_trip_list_fillable() {
        let r = round_trip(
            r#"{"id":6,"op":"list_fillable","ctx":"menu","origin":"https://atlas-cloud.test","kind":"card"}"#,
            6,
            "list_fillable",
        );
        assert!(matches!(
            r,
            Request::ListFillable {
                kind: FillKind::Card,
                ..
            }
        ));
    }

    #[test]
    fn request_json_round_trip_fill_login() {
        let r = round_trip(
            r#"{"id":7,"op":"fill_login","ctx":"overlay","item_id":"x","origin":"https://atlas-cloud.test","fields":["username","password","totp"]}"#,
            7,
            "fill_login",
        );
        let Request::FillLogin { fields, .. } = r else {
            panic!()
        };
        assert_eq!(
            fields,
            vec![FillField::Username, FillField::Password, FillField::Totp]
        );
    }

    #[test]
    fn request_json_round_trip_fill_card() {
        round_trip(
            r#"{"id":8,"op":"fill_card","ctx":"menu","item_id":"x","origin":"https://atlas-cloud.test"}"#,
            8,
            "fill_card",
        );
    }

    #[test]
    fn request_json_round_trip_fill_identity() {
        round_trip(
            r#"{"id":9,"op":"fill_identity","ctx":"menu","item_id":"x","origin":"https://atlas-cloud.test"}"#,
            9,
            "fill_identity",
        );
    }

    #[test]
    fn request_json_round_trip_totp() {
        round_trip(
            r#"{"id":10,"op":"totp","ctx":"popup","item_id":"x"}"#,
            10,
            "totp",
        );
        round_trip(
            r#"{"id":11,"op":"totp","ctx":"chain","item_id":"x","origin":"https://atlas-cloud.test"}"#,
            11,
            "totp",
        );
    }

    #[test]
    fn request_json_round_trip_reveal() {
        round_trip(
            r#"{"id":12,"op":"reveal","ctx":"popup","item_id":"x","field":"password"}"#,
            12,
            "reveal",
        );
    }

    #[test]
    fn request_json_round_trip_check_credentials() {
        let r = round_trip(
            r#"{"id":13,"op":"check_credentials","ctx":"save_prompt","origin":"https://atlas-cloud.test","username":"alex@atlas.dev","password":"pw-x"}"#,
            13,
            "check_credentials",
        );
        assert!(!format!("{r:?}").contains("pw-x"));
    }

    #[test]
    fn request_json_round_trip_save_login() {
        let r = round_trip(
            r#"{"id":14,"op":"save_login","ctx":"save_prompt","origin":"https://atlas-cloud.test","title":"Atlas","username":"alex@atlas.dev","password":"pw-y","vault_id":"v","rule":"exact_host","tags":["work"]}"#,
            14,
            "save_login",
        );
        assert!(matches!(
            r,
            Request::SaveLogin {
                rule: Rule::ExactHost,
                ..
            }
        ));
    }

    #[test]
    fn request_json_round_trip_update_password() {
        round_trip(
            r#"{"id":15,"op":"update_password","ctx":"save_prompt","item_id":"x","origin":"https://atlas-cloud.test","password":"pw-z"}"#,
            15,
            "update_password",
        );
    }

    #[test]
    fn request_json_round_trip_generate() {
        let r = round_trip(
            r#"{"id":16,"op":"generate","ctx":"menu","recipe":{"kind":"random","length":24,"symbols":true}}"#,
            16,
            "generate",
        );
        let Request::Generate { recipe, .. } = r else {
            panic!()
        };
        assert_eq!(recipe.kind, RecipeKind::Random);
        assert_eq!(recipe.length, Some(24));
        round_trip(
            r#"{"id":17,"op":"generate","ctx":"popup","recipe":{"kind":"memorable"}}"#,
            17,
            "generate",
        );
    }

    #[test]
    fn request_json_round_trip_provider_accounts() {
        let r = round_trip(
            r#"{"id":18,"op":"provider_accounts","ctx":"menu","provider":"google","origin":"https://accounts.google.com"}"#,
            18,
            "provider_accounts",
        );
        assert!(matches!(
            r,
            Request::ProviderAccounts {
                provider: ProviderId::Google,
                ..
            }
        ));
    }

    #[test]
    fn request_json_round_trip_fill_provider() {
        round_trip(
            r#"{"id":19,"op":"fill_provider","ctx":"chain","account_item_id":"a","provider":"google","provider_origin":"https://accounts.google.com","site_origin":"https://atlas-cloud.test","fields":["username"]}"#,
            19,
            "fill_provider",
        );
    }

    #[test]
    fn request_json_round_trip_link_provider() {
        round_trip(
            r#"{"id":20,"op":"link_provider","ctx":"save_prompt","site_origin":"https://atlas-cloud.test","provider":"google","account_item_id":"a"}"#,
            20,
            "link_provider",
        );
    }

    #[test]
    fn unknown_field_rejected() {
        for wire in [
            r#"{"id":1,"op":"status","extra":1}"#,
            r#"{"id":1,"op":"search","ctx":"popup","query":"a","x":true}"#,
            r#"{"id":1,"op":"generate","ctx":"menu","recipe":{"kind":"pin","digits":4}}"#,
            r#"{"id":1,"op":"nope"}"#,
            r#"{"id":1,"op":"search","ctx":"page","query":"a"}"#,
            r#"{"id":1,"op":"provider_accounts","ctx":"menu","provider":"Google","origin":"https://a.test"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(wire).is_err(), "{wire}");
        }
    }

    #[test]
    fn replies_have_the_wire_shape() {
        let ok = Reply::Ok {
            id: 3,
            ok: Box::new(Response::Totp {
                code: "123456".into(),
                remaining: 12,
            }),
        };
        assert_eq!(
            serde_json::to_value(&ok).unwrap(),
            json!({"id":3,"ok":{"code":"123456","remaining":12}})
        );
        let empty = Reply::Ok {
            id: 4,
            ok: Box::new(Response::Empty {}),
        };
        assert_eq!(
            serde_json::to_value(&empty).unwrap(),
            json!({"id":4,"ok":{}})
        );
        let err = Reply::Err {
            id: None,
            err: ErrorBody::new(AppErrorCode::Invalid, "malformed request"),
        };
        assert_eq!(
            serde_json::to_value(&err).unwrap(),
            json!({"id":null,"err":{"code":"invalid","msg":"malformed request"}})
        );
        assert!(!format!("{ok:?}").contains("123456"));
    }

    #[test]
    fn summary_has_the_wire_shape() {
        let s = Summary {
            item_id: "i".into(),
            vault_id: "v".into(),
            vault_name: "Perso".into(),
            title: "Atlas Cloud".into(),
            subtitle: "alex@atlas.dev".into(),
            kind: SummaryKind::Login,
            icon_letter: "A".into(),
            icon_color: "#000000".into(),
            has_password: true,
            has_totp: false,
            methods: vec![Method {
                provider: ProviderId::Google,
                account_email: "alex.perso@example.com".into(),
            }],
            match_quality: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["match"], Value::Null);
        assert_eq!(v["kind"], "login");
        assert_eq!(v["methods"][0]["provider"], "google");
        assert_eq!(v.as_object().unwrap().len(), 12);
    }
}
