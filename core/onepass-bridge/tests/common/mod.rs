//! In-memory vault with fictional data for the service tests.

#![allow(dead_code)]

use onepass_bridge::service::{VaultAccess, VaultInfo, VaultStatus};
use onepass_bridge::{AppErrorCode, BridgeError, Result};
use onepass_core::Id;
use onepass_core::model::{
    Address, FieldValue, Item, ItemType, ItemUrl, LoginMethod, MatchRule, Provider, new_item,
};
use time::{Date, Month};
use zeroize::Zeroizing;

/// Fictional TOTP secret of the Atlas Cloud login.
pub const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";
pub const ATLAS_PASSWORD: &str = "Atl4s-Pass-0001";
pub const ADMIN_PASSWORD: &str = "Adm1n-Pass-0002";
pub const ARCHIVED_PASSWORD: &str = "Old-Pass-0003";
pub const HIDDEN_PASSWORD: &str = "Hidden-Pass-0004";
pub const GOOGLE_PERSO_PASSWORD: &str = "G-Perso-0005";
pub const GOOGLE_PRO_PASSWORD: &str = "G-Pro-0006";
pub const REPROMPT_PASSWORD: &str = "Repr-Pass-0007";
pub const NOAUTO_PASSWORD: &str = "NoAuto-Pass-0008";
pub const WALLET_SECRET: &str = "wallet-seed-0009";
pub const CARD_NUMBER: &str = "4242 4242 4242 4242";
pub const CARD_CVV: &str = "737";

/// Every secret of the fixture, for leak checks.
pub const SECRETS: [&str; 12] = [
    TOTP_SECRET,
    ATLAS_PASSWORD,
    ADMIN_PASSWORD,
    ARCHIVED_PASSWORD,
    HIDDEN_PASSWORD,
    GOOGLE_PERSO_PASSWORD,
    GOOGLE_PRO_PASSWORD,
    REPROMPT_PASSWORD,
    NOAUTO_PASSWORD,
    WALLET_SECRET,
    CARD_NUMBER,
    "4242424242424242",
];

pub struct Ids {
    pub perso: Id,
    pub pro: Id,
    pub atlas: Id,
    pub admin: Id,
    pub archived: Id,
    pub hidden: Id,
    pub wallet: Id,
    pub card: Id,
    pub identity: Id,
    pub google_perso: Id,
    pub google_pro: Id,
    pub docs: Id,
    pub reprompt: Id,
    pub noauto: Id,
}

pub struct FakeVault {
    pub locked: bool,
    pub approve_reprompt: bool,
    pub vaults: Vec<VaultInfo>,
    pub items: Vec<Item>,
}

fn set(item: &mut Item, field: &str, value: FieldValue) {
    item.field_mut(field).expect(field).value = value;
}

fn pw(s: &str) -> FieldValue {
    FieldValue::Password(Zeroizing::new(s.to_owned()))
}

fn url(item: &mut Item, u: &str, rule: MatchRule) {
    item.urls.push(ItemUrl {
        label: "site web".into(),
        url: u.into(),
        rule,
        primary: item.urls.is_empty(),
    });
}

fn login(vault: Id, title: &str, user: &str, pass: &str, u: &str, rule: MatchRule) -> Item {
    let mut i = new_item(ItemType::Login, vault, title);
    set(&mut i, "username", FieldValue::Text(user.into()));
    set(&mut i, "password", pw(pass));
    url(&mut i, u, rule);
    i
}

impl FakeVault {
    pub fn new() -> (FakeVault, Ids) {
        let perso = VaultInfo {
            id: Id::new(),
            name: "Personnel".into(),
            color: Some("#5856D6".into()),
        };
        let pro = VaultInfo {
            id: Id::new(),
            name: "Atlas".into(),
            color: None,
        };
        let p = perso.id;

        let mut atlas = login(
            p,
            "Atlas Cloud",
            "alex@atlas.dev",
            ATLAS_PASSWORD,
            "https://atlas-cloud.test",
            MatchRule::Domain,
        );
        set(
            &mut atlas,
            "totp",
            FieldValue::Otp(Zeroizing::new(format!(
                "otpauth://totp/Atlas:alex@atlas.dev?secret={TOTP_SECRET}&issuer=Atlas"
            ))),
        );

        let admin = login(
            pro.id,
            "Atlas admin",
            "admin@atlas.dev",
            ADMIN_PASSWORD,
            "https://admin.atlas-cloud.test",
            MatchRule::ExactHost,
        );

        let mut archived = login(
            p,
            "Atlas ancien",
            "alex@atlas.dev",
            ARCHIVED_PASSWORD,
            "https://atlas-cloud.test",
            MatchRule::Domain,
        );
        archived.archived = true;

        let mut hidden = login(
            p,
            "Atlas cache",
            "alex@atlas.dev",
            HIDDEN_PASSWORD,
            "https://atlas-cloud.test",
            MatchRule::Domain,
        );
        hidden.hide_from_autofill = true;

        let mut wallet = new_item(ItemType::CryptoWallet, p, "Atlas wallet");
        wallet.sections[0].fields.push(onepass_core::model::Field {
            id: "seed".into(),
            label: "Seed".into(),
            kind: onepass_core::model::FieldType::Concealed,
            value: FieldValue::Concealed(Zeroizing::new(WALLET_SECRET.into())),
            required: false,
            repeatable: false,
            autofill: true,
        });
        url(&mut wallet, "https://atlas-cloud.test", MatchRule::Domain);

        let mut card = new_item(ItemType::CreditCard, p, "Carte Atlas");
        set(
            &mut card,
            "cardholder",
            FieldValue::Text("Alex Martin".into()),
        );
        set(
            &mut card,
            "number",
            FieldValue::Concealed(Zeroizing::new(CARD_NUMBER.into())),
        );
        set(
            &mut card,
            "expiry",
            FieldValue::MonthYear {
                year: 2029,
                month: 4,
            },
        );
        set(
            &mut card,
            "cvv",
            FieldValue::Concealed(Zeroizing::new(CARD_CVV.into())),
        );

        let mut identity = new_item(ItemType::Identity, p, "Alex Martin");
        set(&mut identity, "first_name", FieldValue::Text("Alex".into()));
        set(
            &mut identity,
            "last_name",
            FieldValue::Text("Martin".into()),
        );
        set(
            &mut identity,
            "email",
            FieldValue::Email("alex@atlas.dev".into()),
        );
        set(
            &mut identity,
            "mobile_phone",
            FieldValue::Phone("+33 6 00 00 00 00".into()),
        );
        set(
            &mut identity,
            "birth_date",
            FieldValue::Date(Date::from_calendar_date(1990, Month::May, 17).expect("date")),
        );
        set(
            &mut identity,
            "address",
            FieldValue::Address(Address {
                line1: "1 rue de l'Exemple".into(),
                line2: String::new(),
                city: "Lyon".into(),
                postal_code: "69000".into(),
                region: "Rhone".into(),
                country: "FR".into(),
            }),
        );
        set(&mut identity, "company", FieldValue::Text("Atlas".into()));

        let google_perso = login(
            p,
            "Google perso",
            "alex.perso@example.com",
            GOOGLE_PERSO_PASSWORD,
            "https://accounts.google.com",
            MatchRule::ExactHost,
        );
        let google_pro = login(
            pro.id,
            "Google pro",
            "alex.pro@example.com",
            GOOGLE_PRO_PASSWORD,
            "https://accounts.google.com",
            MatchRule::ExactHost,
        );

        let mut docs = new_item(ItemType::Login, p, "Atlas Docs");
        url(
            &mut docs,
            "https://docs.atlas-cloud.test",
            MatchRule::ExactHost,
        );
        docs.login_methods.push(LoginMethod::Provider {
            provider: Provider::Google,
            account: google_perso.id,
            relay_email: None,
        });

        let mut reprompt = login(
            p,
            "Atlas coffre",
            "alex@atlas.dev",
            REPROMPT_PASSWORD,
            "https://vault.atlas-cloud.test",
            MatchRule::ExactHost,
        );
        reprompt.reprompt = true;

        let mut noauto = login(
            p,
            "Atlas sans autofill",
            "alex@atlas.dev",
            NOAUTO_PASSWORD,
            "https://noauto.atlas-cloud.test",
            MatchRule::ExactHost,
        );
        noauto.field_mut("password").expect("password").autofill = false;

        let ids = Ids {
            perso: perso.id,
            pro: pro.id,
            atlas: atlas.id,
            admin: admin.id,
            archived: archived.id,
            hidden: hidden.id,
            wallet: wallet.id,
            card: card.id,
            identity: identity.id,
            google_perso: google_perso.id,
            google_pro: google_pro.id,
            docs: docs.id,
            reprompt: reprompt.id,
            noauto: noauto.id,
        };
        let vault = FakeVault {
            locked: false,
            approve_reprompt: false,
            vaults: vec![perso, pro],
            items: vec![
                atlas,
                admin,
                archived,
                hidden,
                wallet,
                card,
                identity,
                google_perso,
                google_pro,
                docs,
                reprompt,
                noauto,
            ],
        };
        (vault, ids)
    }

    pub fn item(&self, id: Id) -> &Item {
        self.items.iter().find(|i| i.id == id).expect("item")
    }

    fn info(&self, id: Id) -> VaultInfo {
        self.vaults
            .iter()
            .find(|v| v.id == id)
            .cloned()
            .expect("vault")
    }
}

impl VaultAccess for FakeVault {
    fn status(&self) -> VaultStatus {
        VaultStatus {
            locked: self.locked,
            account: "alex@atlas.dev".into(),
            vaults: self.vaults.len(),
        }
    }

    fn unlock(&mut self) -> Result<bool> {
        self.locked = false;
        Ok(true)
    }

    fn vaults(&self) -> Result<Vec<VaultInfo>> {
        if self.locked {
            return Err(BridgeError::App(AppErrorCode::Locked));
        }
        Ok(self.vaults.clone())
    }

    fn items(&mut self) -> Result<Vec<(VaultInfo, Item)>> {
        if self.locked {
            return Err(BridgeError::App(AppErrorCode::Locked));
        }
        Ok(self
            .items
            .iter()
            .map(|i| (self.info(i.vault_id), i.clone()))
            .collect())
    }

    fn save(&mut self, vault_id: Id, mut item: Item) -> Result<()> {
        item.vault_id = vault_id;
        match self.items.iter_mut().find(|i| i.id == item.id) {
            Some(slot) => *slot = item,
            None => self.items.push(item),
        }
        Ok(())
    }

    fn approve_reprompt(&mut self, _item_id: Id) -> bool {
        self.approve_reprompt
    }
}
