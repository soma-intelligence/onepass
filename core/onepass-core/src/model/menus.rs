//! Options of the menu fields of the templates. Menus are free strings in
//! stored items; the options only feed the pickers of the apps.

use crate::model::templates::ItemType;

const YES_NO: &[&str] = &["oui", "non"];

/// The options of the menu field `field_id` of items of type `t`. A field
/// without a known list (not a menu, or an unknown id) gives an empty
/// slice: the apps then show a free text field.
pub fn menu_options(t: ItemType, field_id: &str) -> &'static [&'static str] {
    use ItemType as T;
    match (t, field_id) {
        (T::Email, "account_type") => &["IMAP", "POP", "Exchange", "JMAP"],
        (T::Email, "incoming_security" | "smtp_security") => &["SSL/TLS", "STARTTLS", "Aucune"],
        (T::Email, "incoming_auth") => &["Mot de passe", "OAuth2", "Aucune"],
        (T::Server, "protocol") => &["SSH", "RDP", "VNC", "HTTPS", "SFTP", "FTP"],
        (T::Server | T::Database | T::ApiCredential, "environment") => {
            &["Production", "Staging", "Développement"]
        }
        (T::Database, "engine") => &[
            "PostgreSQL",
            "MySQL",
            "MariaDB",
            "SQL Server",
            "Oracle",
            "MongoDB",
            "Redis",
            "SQLite",
            "ClickHouse",
            "Cassandra",
            "Elasticsearch",
            "Autre",
        ],
        (T::Database, "ssl_mode") => &[
            "Désactivé",
            "Préféré",
            "Requis",
            "Vérifier le CA",
            "Vérification complète",
        ],
        (T::Router, "security") => &["WPA3", "WPA2", "WPA", "WEP", "Ouvert"],
        (T::Router, "band") => &["2,4 GHz", "5 GHz", "6 GHz"],
        (T::ApiCredential, "credential_type") => {
            &["Clé API", "Bearer", "Basic", "OAuth2 client", "HMAC", "JWT"]
        }
        (T::SshKey, "algorithm") => &["Ed25519", "ECDSA P-256", "ECDSA P-384", "RSA 4096"],
        (T::CreditCard, "card_type") => &["Crédit", "Débit", "Prépayée"],
        (T::BankAccount, "account_type") => &["Courant", "Épargne", "Pro", "Joint", "Autre"],
        (T::CryptoWallet, "wallet_type") => &["Logiciel", "Matériel", "Papier", "Exchange"],
        (T::Subscription, "frequency") => &["Mensuel", "Annuel", "Autre"],
        (T::Identity | T::IdCard | T::Passport | T::DriverLicense, "sex") => {
            &["Féminin", "Masculin", "Autre"]
        }
        (T::Passport, "passport_type") => &["Ordinaire", "Diplomatique", "Service", "Autre"],
        (T::MedicalRecord, "blood_type") => &["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"],
        (T::Insurance, "insurance_type") => &[
            "Auto",
            "Habitation",
            "Santé",
            "Vie",
            "Voyage",
            "Responsabilité civile",
            "Autre",
        ],
        (T::Insurance, "premium_frequency") => &["Mensuel", "Trimestriel", "Annuel", "Autre"],
        (T::AccessCode, "tag") => &["Portail", "Immeuble", "Alarme", "Casier", "Garage"],
        // Yes/no switches, built by `yn` in the templates.
        (T::Database, "read_only")
        | (T::Router, "hidden")
        | (T::SshKey, "use_in_agent" | "confirm_each_use" | "git_signing")
        | (T::CreditCard, "virtual")
        | (T::DriverLicense | T::MedicalRecord, "organ_donor") => YES_NO,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::field::FieldType;
    use crate::model::templates::template;

    #[test]
    fn every_menu_field_has_options() {
        let mut seen = 0;
        for t in ItemType::ALL {
            for section in template(t) {
                for f in section.fields {
                    if f.kind == FieldType::Menu {
                        seen += 1;
                        let options = menu_options(t, &f.id);
                        assert!(options.len() >= 2, "{t:?} {}", f.id);
                    }
                }
            }
        }
        // 27 menus with their own options and 8 yes/no switches.
        assert_eq!(seen, 35, "templates changed shape: {seen}");
    }

    #[test]
    fn database_engine_options() {
        assert_eq!(
            menu_options(ItemType::Database, "engine"),
            [
                "PostgreSQL",
                "MySQL",
                "MariaDB",
                "SQL Server",
                "Oracle",
                "MongoDB",
                "Redis",
                "SQLite",
                "ClickHouse",
                "Cassandra",
                "Elasticsearch",
                "Autre"
            ]
        );
    }

    #[test]
    fn yes_no_fields_offer_oui_non() {
        assert_eq!(
            menu_options(ItemType::Database, "read_only"),
            ["oui", "non"]
        );
        assert_eq!(
            menu_options(ItemType::SshKey, "git_signing"),
            ["oui", "non"]
        );
    }

    #[test]
    fn spec_values_are_verbatim() {
        assert_eq!(
            menu_options(ItemType::Router, "security"),
            ["WPA3", "WPA2", "WPA", "WEP", "Ouvert"]
        );
        assert_eq!(
            menu_options(ItemType::Identity, "sex"),
            ["Féminin", "Masculin", "Autre"]
        );
        assert_eq!(
            menu_options(ItemType::Server, "environment")[2],
            "Développement"
        );
    }

    #[test]
    fn unknown_field_is_free_text() {
        assert!(menu_options(ItemType::Login, "username").is_empty());
        assert!(menu_options(ItemType::Database, "nope").is_empty());
    }
}
