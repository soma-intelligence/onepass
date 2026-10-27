//! The 26 item templates. Field ids are stable snake_case English names,
//! labels are French display text. A field marked `required` is the spec's
//! `*` field. Masking of secret kinds (Password, Concealed, Otp, Mnemonic)
//! is implied by the field kind: `Field` carries no separate flag.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::id::Id;
use crate::model::field::{Field, FieldType as K, FieldValue, Section};
use crate::model::item::Item;

/// Kind of an item. Postcard encodes variants by index: new variants must
/// only ever be appended at the end, never inserted or reordered (pinned by
/// `model::wire_tests`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemType {
    Login,
    SecureNote,
    Password,
    Email,
    Server,
    Database,
    Router,
    ApiCredential,
    SshKey,
    CreditCard,
    BankAccount,
    CryptoWallet,
    Subscription,
    Identity,
    IdCard,
    Passport,
    DriverLicense,
    SocialSecurityNumber,
    MedicalRecord,
    Membership,
    RewardProgram,
    Insurance,
    Vehicle,
    AccessCode,
    Document,
    SoftwareLicense,
}

impl ItemType {
    /// Every type, in the order of the spec (section 5.4).
    pub const ALL: [ItemType; 26] = [
        ItemType::Login,
        ItemType::Password,
        ItemType::Email,
        ItemType::Server,
        ItemType::Database,
        ItemType::Router,
        ItemType::ApiCredential,
        ItemType::SshKey,
        ItemType::CreditCard,
        ItemType::BankAccount,
        ItemType::CryptoWallet,
        ItemType::Subscription,
        ItemType::Identity,
        ItemType::IdCard,
        ItemType::Passport,
        ItemType::DriverLicense,
        ItemType::SocialSecurityNumber,
        ItemType::MedicalRecord,
        ItemType::Membership,
        ItemType::RewardProgram,
        ItemType::Insurance,
        ItemType::Vehicle,
        ItemType::AccessCode,
        ItemType::SecureNote,
        ItemType::Document,
        ItemType::SoftwareLicense,
    ];
}

// Builders. One per field kind keeps each template a plain list.

fn fld(id: &str, label: &str, kind: K) -> Field {
    Field {
        id: id.into(),
        label: label.into(),
        kind,
        value: FieldValue::Empty,
        required: false,
        repeatable: false,
        autofill: true,
    }
}

fn tx(id: &str, l: &str) -> Field {
    fld(id, l, K::Text)
}
fn pw(id: &str, l: &str) -> Field {
    fld(id, l, K::Password)
}
fn cn(id: &str, l: &str) -> Field {
    fld(id, l, K::Concealed)
}
fn url(id: &str, l: &str) -> Field {
    fld(id, l, K::Url)
}
fn em(id: &str, l: &str) -> Field {
    fld(id, l, K::Email)
}
fn ph(id: &str, l: &str) -> Field {
    fld(id, l, K::Phone)
}
fn dt(id: &str, l: &str) -> Field {
    fld(id, l, K::Date)
}
fn my(id: &str, l: &str) -> Field {
    fld(id, l, K::MonthYear)
}
fn num(id: &str, l: &str) -> Field {
    fld(id, l, K::Number)
}
fn mon(id: &str, l: &str) -> Field {
    fld(id, l, K::Money)
}
fn adr(id: &str, l: &str) -> Field {
    fld(id, l, K::Address)
}
fn menu(id: &str, l: &str) -> Field {
    fld(id, l, K::Menu)
}
fn otp(id: &str, l: &str) -> Field {
    fld(id, l, K::Otp)
}
fn file(id: &str, l: &str) -> Field {
    fld(id, l, K::File)
}
fn link(id: &str, l: &str) -> Field {
    fld(id, l, K::ItemLink)
}
/// Yes/no switch, stored as a two-entry menu ("oui" / "non").
fn yn(id: &str, l: &str) -> Field {
    fld(id, l, K::Menu)
}

trait FieldExt {
    fn req(self) -> Self;
    fn rep(self) -> Self;
}

impl FieldExt for Field {
    fn req(mut self) -> Self {
        self.required = true;
        self
    }
    fn rep(mut self) -> Self {
        self.repeatable = true;
        self
    }
}

fn sec(id: &str, label: &str, fields: Vec<Field>) -> Section {
    Section {
        id: id.into(),
        label: label.into(),
        fields,
    }
}

/// Sections and empty fields of a new item of this type.
pub fn template(t: ItemType) -> Vec<Section> {
    match t {
        ItemType::Login => login(),
        ItemType::Password => password(),
        ItemType::Email => email(),
        ItemType::Server => server(),
        ItemType::Database => database(),
        ItemType::Router => router(),
        ItemType::ApiCredential => api_credential(),
        ItemType::SshKey => ssh_key(),
        ItemType::CreditCard => credit_card(),
        ItemType::BankAccount => bank_account(),
        ItemType::CryptoWallet => crypto_wallet(),
        ItemType::Subscription => subscription(),
        ItemType::Identity => identity(),
        ItemType::IdCard => id_card(),
        ItemType::Passport => passport(),
        ItemType::DriverLicense => driver_license(),
        ItemType::SocialSecurityNumber => social_security_number(),
        ItemType::MedicalRecord => medical_record(),
        ItemType::Membership => membership(),
        ItemType::RewardProgram => reward_program(),
        ItemType::Insurance => insurance(),
        ItemType::Vehicle => vehicle(),
        ItemType::AccessCode => access_code(),
        ItemType::SecureNote => secure_note(),
        ItemType::Document => document(),
        ItemType::SoftwareLicense => software_license(),
    }
}

/// A new item with an empty template; timestamps are now.
pub fn new_item(t: ItemType, vault_id: Id, title: &str) -> Item {
    let now = OffsetDateTime::now_utc();
    Item {
        id: Id::new(),
        vault_id,
        item_type: t,
        title: title.into(),
        tags: Vec::new(),
        favorite: false,
        color: None,
        custom_icon: None,
        notes: String::new(),
        urls: Vec::new(),
        apps: Vec::new(),
        locations: Vec::new(),
        login_methods: Vec::new(),
        sections: template(t),
        attachments: Vec::new(),
        expires: None,
        rotate_every_days: None,
        reprompt: false,
        hide_from_autofill: false,
        watchtower_exclusions: Vec::new(),
        on_watch: false,
        archived: false,
        trashed_at: None,
        created_at: now,
        updated_at: now,
        password_history: Vec::new(),
        events: Vec::new(),
    }
}

fn login() -> Vec<Section> {
    vec![sec(
        "main",
        "Connexion",
        vec![
            tx("username", "Identifiant").req(),
            pw("password", "Mot de passe"),
            em("email", "Email"),
            otp("totp", "TOTP"),
            fld("passkeys", "Passkeys", K::Passkey).rep(),
            cn("pin", "PIN"),
            ph("recovery_phone", "Téléphone pour la 2FA"),
            cn("backup_codes", "Codes de secours 2FA").rep(),
            tx("security_question", "Question de sécurité").rep(),
            // Paired with `security_question` by order; masked as Concealed.
            cn("security_answer", "Réponse").rep(),
        ],
    )]
}

fn password() -> Vec<Section> {
    vec![sec(
        "main",
        "Mot de passe",
        vec![
            pw("password", "Mot de passe").req(),
            tx("context", "Contexte"),
            tx("generator_rules", "Règles de génération utilisées"),
        ],
    )]
}

fn email() -> Vec<Section> {
    vec![
        sec(
            "main",
            "Compte",
            vec![
                em("address", "Adresse").req(),
                pw("password", "Mot de passe"),
                pw("app_password", "Mot de passe d'application"),
                tx("provider", "Fournisseur"),
                menu("account_type", "Type de compte"),
                em("alias", "Alias").rep(),
                em("recovery_email", "Email de récupération"),
                ph("recovery_phone", "Téléphone de récupération"),
                otp("totp", "TOTP"),
            ],
        ),
        sec(
            "incoming",
            "Entrant",
            vec![
                tx("incoming_server", "Serveur"),
                num("incoming_port", "Port"),
                menu("incoming_security", "Sécurité"),
                menu("incoming_auth", "Méthode d'auth"),
                tx("incoming_username", "Identifiant"),
            ],
        ),
        sec(
            "outgoing",
            "Sortant (SMTP)",
            vec![
                tx("smtp_server", "Serveur"),
                num("smtp_port", "Port"),
                menu("smtp_security", "Sécurité"),
                tx("smtp_username", "Identifiant"),
                pw("smtp_password", "Mot de passe"),
            ],
        ),
    ]
}

fn server() -> Vec<Section> {
    vec![
        sec(
            "main",
            "Serveur",
            vec![
                tx("host", "Hôte ou IP").req(),
                num("port", "Port"),
                menu("protocol", "Protocole"),
                tx("username", "Utilisateur"),
                pw("password", "Mot de passe"),
                link("ssh_key", "Clé SSH"),
                tx("host_fingerprint", "Empreinte d'hôte"),
                link("bastion", "Bastion"),
                link("vpn", "VPN requis"),
                tx("os", "OS"),
                tx("ipv4", "IPv4"),
                tx("ipv6", "IPv6"),
                tx("region", "Région"),
                menu("environment", "Environnement"),
                otp("totp", "TOTP"),
            ],
        ),
        sec(
            "admin",
            "Admin",
            vec![
                url("admin_url", "URL du panneau"),
                tx("admin_username", "Utilisateur"),
                pw("admin_password", "Mot de passe"),
            ],
        ),
        sec(
            "hosting",
            "Hébergeur",
            vec![
                tx("hosting_name", "Nom"),
                url("hosting_console_url", "URL console"),
                link("hosting_account", "Compte"),
                ph("hosting_support_phone", "Téléphone support"),
            ],
        ),
    ]
}

fn database() -> Vec<Section> {
    vec![sec(
        "main",
        "Base de données",
        vec![
            menu("engine", "Moteur").req(),
            tx("host", "Hôte").req(),
            num("port", "Port"),
            tx("database", "Base"),
            tx("schema", "Schéma"),
            tx("username", "Utilisateur"),
            pw("password", "Mot de passe"),
            tx("service_name", "SID ou nom de service"),
            menu("ssl_mode", "Mode SSL"),
            file("ca_certificate", "Certificat CA"),
            file("client_certificate", "Certificat client"),
            cn("client_key", "Clé client"),
            tx("connection_options", "Options de connexion"),
            link("ssh_tunnel", "Tunnel SSH"),
            menu("environment", "Environnement"),
            yn("read_only", "Lecture seule"),
            tx("alias", "Alias"),
            // Computed: the connection string is derived, not stored.
        ],
    )]
}

fn router() -> Vec<Section> {
    vec![sec(
        "main",
        "Wi-Fi",
        vec![
            tx("ssid", "SSID").req(),
            pw("wifi_password", "Mot de passe Wi-Fi"),
            menu("security", "Sécurité"),
            menu("band", "Bande"),
            yn("hidden", "Réseau masqué"),
            tx("guest_ssid", "SSID invité"),
            pw("guest_password", "Mot de passe invité"),
            tx("model", "Modèle"),
            tx("serial_number", "Numéro de série"),
            tx("mac_address", "Adresse MAC"),
            tx("firmware_version", "Version du firmware"),
            url("admin_address", "IP ou URL admin"),
            tx("admin_username", "Utilisateur admin"),
            pw("admin_password", "Mot de passe admin"),
            tx("isp", "FAI"),
            tx("isp_customer_number", "Numéro client FAI"),
            cn("pppoe_credentials", "Identifiants PPPoE"),
            tx("public_ip", "IP publique"),
            tx("dns", "DNS"),
            // Computed: the connection QR code is derived, not stored.
        ],
    )]
}

fn api_credential() -> Vec<Section> {
    vec![sec(
        "main",
        "Accès API",
        vec![
            tx("service", "Service").req(),
            cn("key", "Clé ou token").req(),
            cn("secret", "Secret"),
            tx("client_id", "Client ID"),
            menu("credential_type", "Type"),
            menu("environment", "Environnement"),
            url("base_url", "URL de base"),
            tx("scopes", "Scopes"),
            tx("header_name", "Nom de l'en-tête HTTP"),
            cn("webhook_secret", "Secret de webhook"),
            tx("env_var_name", "Nom de variable d'environnement"),
            dt("created_on", "Créée le"),
            dt("expires_on", "Expire le"),
            url("console_url", "URL de la console"),
            link("linked_account", "Compte lié"),
        ],
    )]
}

fn ssh_key() -> Vec<Section> {
    vec![sec(
        "main",
        "Clé SSH",
        vec![
            fld("private_key", "Clé privée", K::SshKey).req(),
            menu("algorithm", "Algorithme"),
            cn("passphrase", "Passphrase"),
            tx("comment", "Commentaire"),
            file("certificate", "Certificat SSH"),
            tx("hosts", "Hôtes associés").rep(),
            yn("use_in_agent", "Utiliser dans l'agent"),
            yn("confirm_each_use", "Confirmer à chaque usage"),
            yn("git_signing", "Signature Git"),
            // Computed: public key and SHA256 fingerprint come from the key.
        ],
    )]
}

fn credit_card() -> Vec<Section> {
    vec![sec(
        "main",
        "Carte",
        vec![
            tx("cardholder", "Titulaire").req(),
            cn("number", "Numéro").req(),
            my("expiry", "Expiration").req(),
            cn("cvv", "CVV"),
            cn("pin", "PIN"),
            menu("card_type", "Type"),
            yn("virtual", "Carte virtuelle"),
            dt("issued_on", "Date d'émission"),
            tx("issuer", "Banque émettrice"),
            tx("currency", "Devise"),
            mon("limit", "Plafond"),
            adr("billing_address", "Adresse de facturation"),
            ph("support_phone_local", "Téléphone support (local)"),
            ph(
                "support_phone_international",
                "Téléphone support (international)",
            ),
            url("bank_url", "Site de la banque"),
            // Computed: the card brand is derived from the BIN.
        ],
    )]
}

fn bank_account() -> Vec<Section> {
    vec![sec(
        "main",
        "Compte bancaire",
        vec![
            tx("bank", "Banque").req(),
            tx("holder", "Titulaire").req(),
            menu("account_type", "Type"),
            tx("iban", "IBAN"),
            tx("bic", "BIC/SWIFT"),
            tx("account_number", "Numéro de compte"),
            tx("bank_code", "Code banque"),
            tx("branch_code", "Code guichet"),
            tx("rib_key", "Clé RIB"),
            tx("routing_number", "Routing number (US)"),
            tx("sort_code", "Sort code (UK)"),
            tx("currency", "Devise"),
            cn("pin", "PIN"),
            link("online_banking", "Banque en ligne"),
            tx("advisor_name", "Conseiller (nom)"),
            ph("advisor_phone", "Conseiller (téléphone)"),
            em("advisor_email", "Conseiller (email)"),
            adr("branch_address", "Adresse de l'agence"),
            dt("opened_on", "Ouvert le"),
        ],
    )]
}

/// Never autofilled: every field of this template has `autofill: false`.
fn crypto_wallet() -> Vec<Section> {
    let mut sections = vec![sec(
        "main",
        "Wallet",
        vec![
            tx("name", "Nom").req(),
            fld("recovery_phrase", "Phrase de récupération", K::Mnemonic).req(),
            menu("wallet_type", "Type"),
            tx("blockchains", "Blockchains").rep(),
            cn("bip39_passphrase", "Passphrase BIP39"),
            pw("wallet_password", "Mot de passe du wallet"),
            cn("pin", "PIN"),
            cn("private_key", "Clé privée"),
            tx("public_addresses", "Adresses publiques (réseau, adresse)").rep(),
            tx("xpub", "xpub"),
            tx("derivation_path", "Chemin de dérivation"),
            tx("hardware_model", "Modèle du matériel"),
            tx("hardware_serial", "Numéro de série du matériel"),
            link("exchange", "Exchange"),
            dt("created_on", "Créé le"),
            tx("backup_location", "Emplacement de la sauvegarde physique"),
        ],
    )];
    for field in sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        field.autofill = false;
    }
    sections
}

fn subscription() -> Vec<Section> {
    vec![sec(
        "main",
        "Abonnement",
        vec![
            tx("service", "Service").req(),
            mon("price", "Prix"),
            tx("currency", "Devise"),
            menu("frequency", "Fréquence"),
            dt("next_renewal", "Prochain renouvellement"),
            link("payment_method", "Moyen de paiement"),
            dt("started_on", "Début"),
            tx("cancellation_notice", "Préavis de résiliation"),
            url("cancellation_url", "URL de résiliation"),
            link("account", "Compte"),
            num("reminder_days", "Rappel (jours avant le renouvellement)"),
        ],
    )]
}

fn identity() -> Vec<Section> {
    vec![
        sec(
            "main",
            "Identité",
            vec![
                tx("honorific", "Civilité"),
                tx("first_name", "Prénom").req(),
                tx("middle_name", "Deuxième prénom"),
                tx("last_name", "Nom"),
                tx("birth_name", "Nom de naissance"),
                menu("sex", "Sexe"),
                dt("birth_date", "Date de naissance"),
                tx("birth_place", "Lieu de naissance"),
                tx("nationality", "Nationalité"),
                adr("address", "Adresse"),
                ph("mobile_phone", "Téléphone mobile"),
                ph("home_phone", "Téléphone domicile"),
                ph("work_phone", "Téléphone pro"),
                em("email", "Email"),
            ],
        ),
        sec(
            "work",
            "Travail",
            vec![
                tx("company", "Entreprise"),
                tx("job_title", "Poste"),
                tx("department", "Service"),
                url("website", "Site web"),
                tx("handles", "Pseudos (réseau, pseudo)").rep(),
            ],
        ),
    ]
}

fn id_card() -> Vec<Section> {
    vec![sec(
        "main",
        "Carte d'identité",
        vec![
            tx("country", "Pays").req(),
            cn("number", "Numéro").req(),
            dt("expiry", "Expiration").req(),
            tx("last_name", "Nom"),
            tx("first_names", "Prénoms"),
            tx("usage_name", "Nom d'usage"),
            dt("birth_date", "Date de naissance"),
            tx("birth_place", "Lieu de naissance"),
            menu("sex", "Sexe"),
            tx("nationality", "Nationalité"),
            tx("height", "Taille"),
            adr("address", "Adresse"),
            dt("issued_on", "Date d'émission"),
            tx("authority", "Autorité"),
            cn("can_number", "Numéro CAN"),
            tx("mrz", "Lignes MRZ"),
            file("scan_front", "Scan recto"),
            file("scan_back", "Scan verso"),
        ],
    )]
}

fn passport() -> Vec<Section> {
    vec![sec(
        "main",
        "Passeport",
        vec![
            tx("issuing_country", "Pays émetteur").req(),
            cn("number", "Numéro").req(),
            dt("expiry", "Expiration").req(),
            menu("passport_type", "Type"),
            tx("last_name", "Nom"),
            tx("first_names", "Prénoms"),
            tx("nationality", "Nationalité"),
            dt("birth_date", "Date de naissance"),
            tx("birth_place", "Lieu de naissance"),
            menu("sex", "Sexe"),
            dt("issued_on", "Date d'émission"),
            tx("authority", "Autorité"),
            tx("issue_place", "Lieu de délivrance"),
            tx("mrz", "Lignes MRZ"),
            file("scan", "Scan"),
        ],
    )]
}

fn driver_license() -> Vec<Section> {
    vec![sec(
        "main",
        "Permis de conduire",
        vec![
            tx("full_name", "Nom complet").req(),
            cn("number", "Numéro").req(),
            tx("country", "Pays"),
            tx("region", "Région"),
            dt("birth_date", "Date de naissance"),
            adr("address", "Adresse"),
            tx("categories", "Catégories").rep(),
            dt("issued_on", "Date d'émission"),
            dt("expiry", "Expiration"),
            tx("restrictions", "Restrictions"),
            tx("authority", "Autorité"),
            menu("sex", "Sexe"),
            tx("height", "Taille"),
            tx("eye_color", "Couleur des yeux"),
            yn("organ_donor", "Donneur d'organes"),
            file("scan_front", "Scan recto"),
            file("scan_back", "Scan verso"),
        ],
    )]
}

fn social_security_number() -> Vec<Section> {
    vec![sec(
        "main",
        "Sécurité sociale",
        vec![
            tx("name", "Nom").req(),
            cn("number", "Numéro").req(),
            tx("country", "Pays"),
            dt("issued_on", "Date d'émission"),
            file("scan", "Scan"),
        ],
    )]
}

fn medical_record() -> Vec<Section> {
    vec![
        sec(
            "main",
            "Patient",
            vec![
                tx("patient", "Patient").req(),
                dt("birth_date", "Date de naissance"),
                menu("blood_type", "Groupe sanguin"),
                tx("height", "Taille"),
                tx("weight", "Poids"),
                tx("allergies", "Allergies").rep(),
                tx("history", "Antécédents").rep(),
                tx("treatments", "Traitements (médicament, dose, fréquence)").rep(),
                tx("vaccines", "Vaccins (nom, date, lot)").rep(),
                tx("directives", "Directives anticipées"),
                yn("organ_donor", "Donneur d'organes"),
            ],
        ),
        sec(
            "care",
            "Soins",
            vec![
                tx("doctor_name", "Médecin traitant (nom)"),
                ph("doctor_phone", "Médecin traitant (téléphone)"),
                adr("doctor_address", "Médecin traitant (adresse)"),
                tx("facility", "Établissement"),
                tx("record_number", "Numéro de dossier"),
                tx("insurer", "Assureur santé"),
                cn("insurance_member_number", "Numéro d'adhérent"),
                tx("insurance_group_number", "Numéro de groupe"),
                link("emergency_contact", "Contact d'urgence"),
            ],
        ),
    ]
}

fn membership() -> Vec<Section> {
    vec![sec(
        "main",
        "Adhésion",
        vec![
            tx("organization", "Organisation").req(),
            cn("member_number", "Numéro de membre").req(),
            tx("member_name", "Nom du membre"),
            tx("level", "Niveau"),
            dt("joined_on", "Adhésion le"),
            dt("expiry", "Expiration"),
            cn("pin", "PIN"),
            fld("barcode", "Code-barres", K::Barcode),
            ph("phone", "Téléphone"),
            url("website", "Site"),
            adr("address", "Adresse"),
        ],
    )]
}

fn reward_program() -> Vec<Section> {
    vec![sec(
        "main",
        "Fidélité",
        vec![
            tx("company", "Entreprise").req(),
            cn("member_number", "Numéro de membre").req(),
            tx("member_name", "Nom du membre"),
            cn("pin", "PIN"),
            tx("level", "Niveau"),
            num("points_balance", "Solde de points"),
            dt("points_expiry", "Expiration des points"),
            fld("barcode", "Code-barres", K::Barcode),
            ph("phone", "Téléphone"),
            url("website", "Site"),
            link("online_account", "Compte en ligne"),
        ],
    )]
}

fn insurance() -> Vec<Section> {
    vec![sec(
        "main",
        "Assurance",
        vec![
            tx("insurer", "Assureur").req(),
            cn("policy_number", "Numéro de contrat").req(),
            menu("insurance_type", "Type"),
            tx("insured", "Assurés"),
            link("insured_asset", "Bien couvert"),
            dt("started_on", "Début"),
            dt("renewal_date", "Échéance"),
            mon("premium", "Prime"),
            menu("premium_frequency", "Fréquence de la prime"),
            mon("deductible", "Franchise"),
            tx("coverages", "Garanties"),
            ph("assistance_phone", "Numéro d'assistance"),
            tx("claim_number", "Numéro de déclaration de sinistre"),
            tx("advisor", "Conseiller"),
            link("customer_area", "Espace client"),
            file("certificate", "Attestation"),
        ],
    )]
}

fn vehicle() -> Vec<Section> {
    vec![sec(
        "main",
        "Véhicule",
        vec![
            tx("registration", "Immatriculation").req(),
            tx("make", "Marque"),
            tx("model", "Modèle"),
            tx("version", "Version"),
            num("year", "Année"),
            tx("color", "Couleur"),
            tx("vin", "VIN"),
            dt("first_registration", "Première mise en circulation"),
            cn("registration_certificate_number", "Carte grise (numéro)"),
            file("registration_certificate_scan", "Carte grise (scan)"),
            tx("holder", "Titulaire"),
            cn("start_code", "Code de démarrage ou d'autoradio"),
            dt("next_inspection", "Prochain contrôle technique"),
            dt("next_service", "Prochain entretien"),
            link("insurance", "Assurance"),
            num("key_count", "Clés (nombre)"),
            tx("key_location", "Clés (emplacement)"),
        ],
    )]
}

fn access_code() -> Vec<Section> {
    vec![sec(
        "main",
        "Code d'accès",
        vec![
            cn("code", "Code").req(),
            fld("place", "Lieu", K::Location).req(),
            menu("tag", "Étiquette"),
            tx("valid_hours", "Horaires de validité"),
            cn("alarm_code", "Code de l'alarme"),
            tx("instructions", "Instructions"),
            tx("contact", "Contact"),
        ],
    )]
}

fn secure_note() -> Vec<Section> {
    vec![sec(
        "main",
        "Note",
        vec![tx("content", "Contenu (Markdown)").req()],
    )]
}

fn document() -> Vec<Section> {
    vec![sec(
        "main",
        "Document",
        vec![
            file("files", "Fichiers").req().rep(),
            dt("document_date", "Date du document"),
            dt("expiry", "Expiration"),
            tx("issuer", "Émetteur"),
            // Computed: locally extracted OCR text, encrypted, for search.
        ],
    )]
}

fn software_license() -> Vec<Section> {
    vec![sec(
        "main",
        "Licence",
        vec![
            tx("software", "Logiciel").req(),
            cn("license_key", "Clé de licence").req(),
            tx("version", "Version"),
            file("license_file", "Fichier de licence"),
            tx("licensee_name", "Licencié (nom)"),
            em("licensee_email", "Licencié (email)"),
            tx("company", "Entreprise"),
            num("seats", "Nombre de postes"),
            tx("platforms", "Plateformes"),
            dt("purchased_on", "Acheté le"),
            mon("price", "Prix"),
            tx("order_number", "Numéro de commande"),
            url("reseller_website", "Revendeur (site)"),
            em("reseller_support_email", "Revendeur (email support)"),
            dt("updates_until", "Mises à jour jusqu'au"),
            url("download_url", "Lien de téléchargement"),
            link("account", "Compte"),
        ],
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, ValidationError};
    use crate::model::field::{Address, FieldValue};
    use crate::model::validate::validate;
    use time::macros::date;
    use zeroize::Zeroizing;

    fn req(t: ItemType) -> Vec<String> {
        template(t)
            .into_iter()
            .flat_map(|s| s.fields)
            .filter(|f| f.required)
            .map(|f| f.id)
            .collect()
    }

    #[test]
    fn there_are_exactly_26_types_each_with_a_template() {
        assert_eq!(ItemType::ALL.len(), 26);
        for t in ItemType::ALL {
            assert!(!template(t).is_empty(), "{t:?}");
        }
    }

    #[test]
    fn required_fields_match_spec() {
        assert_eq!(req(ItemType::Login), ["username"]);
        assert_eq!(
            req(ItemType::CreditCard),
            ["cardholder", "number", "expiry"]
        );
        assert_eq!(req(ItemType::Database), ["engine", "host"]);
        assert_eq!(req(ItemType::Router), ["ssid"]);
        assert_eq!(req(ItemType::CryptoWallet), ["name", "recovery_phrase"]);
        assert_eq!(
            req(ItemType::Passport),
            ["issuing_country", "number", "expiry"]
        );
        assert_eq!(req(ItemType::IdCard), ["country", "number", "expiry"]);
        assert_eq!(req(ItemType::AccessCode), ["code", "place"]);
        assert_eq!(req(ItemType::Subscription), ["service"]);
    }

    #[test]
    fn crypto_wallet_is_never_autofilled() {
        assert!(
            template(ItemType::CryptoWallet)
                .iter()
                .flat_map(|s| &s.fields)
                .all(|f| !f.autofill)
        );
    }

    #[test]
    fn validate_reports_missing_required_field() {
        let item = new_item(ItemType::CreditCard, Id::new(), "Visa");
        let err = validate(&item).unwrap_err();
        assert!(
            matches!(err, Error::Validation(ValidationError { ref field, .. }) if field == "cardholder")
        );
    }

    #[test]
    fn validate_rejects_empty_title() {
        let item = new_item(ItemType::Login, Id::new(), "  ");
        assert!(matches!(
            validate(&item),
            Err(Error::Validation(ValidationError { ref field, .. })) if field == "title"
        ));
    }

    #[test]
    fn no_field_id_is_title() {
        // `title` is the item's own title in references and `--field`.
        for t in ItemType::ALL {
            for section in template(t) {
                for f in &section.fields {
                    assert_ne!(f.id, "title", "{t:?}");
                }
            }
        }
    }

    #[test]
    fn template_ids_are_unique_within_a_type() {
        for t in ItemType::ALL {
            let mut ids: Vec<String> = template(t)
                .into_iter()
                .flat_map(|s| s.fields)
                .map(|f| f.id)
                .collect();
            let n = ids.len();
            ids.sort();
            ids.dedup();
            assert_eq!(ids.len(), n, "duplicate field id in {t:?}");
        }
    }

    #[test]
    fn new_item_starts_with_all_values_empty() {
        for t in ItemType::ALL {
            let item = new_item(t, Id::new(), "x");
            assert_eq!(item.item_type, t);
            assert!(
                item.sections
                    .iter()
                    .flat_map(|s| &s.fields)
                    .all(|f| f.value == FieldValue::Empty)
            );
        }
    }

    fn tx(s: &str) -> FieldValue {
        FieldValue::Text(s.into())
    }
    fn pw(s: &str) -> FieldValue {
        FieldValue::Password(Zeroizing::new(s.into()))
    }
    fn cn(s: &str) -> FieldValue {
        FieldValue::Concealed(Zeroizing::new(s.into()))
    }
    fn menu(s: &str) -> FieldValue {
        FieldValue::Menu(s.into())
    }
    fn exp() -> FieldValue {
        FieldValue::MonthYear {
            year: 2030,
            month: 12,
        }
    }

    /// One row per type: the required fields filled with plausible values.
    fn valid_rows() -> Vec<(ItemType, Vec<(&'static str, FieldValue)>)> {
        use ItemType::*;
        vec![
            (Login, vec![("username", tx("quentin"))]),
            (Password, vec![("password", pw("correct horse"))]),
            (Email, vec![("address", FieldValue::Email("a@b.co".into()))]),
            (Server, vec![("host", tx("203.0.113.7"))]),
            (
                Database,
                vec![("engine", menu("PostgreSQL")), ("host", tx("db.internal"))],
            ),
            (Router, vec![("ssid", tx("HomeNet"))]),
            (
                ApiCredential,
                vec![("service", tx("Stripe")), ("key", cn("sk_test_123"))],
            ),
            (
                SshKey,
                vec![(
                    "private_key",
                    FieldValue::SshKey(crate::model::field::SshKeyValue {
                        private_pem: Zeroizing::new("pem".into()),
                        public_openssh: "ssh-ed25519 AAAA".into(),
                        fingerprint_sha256: "SHA256:abc".into(),
                    }),
                )],
            ),
            (
                CreditCard,
                vec![
                    ("cardholder", tx("Q CARON")),
                    ("number", cn("4111111111111111")),
                    ("expiry", exp()),
                ],
            ),
            (
                BankAccount,
                vec![("bank", tx("BNP")), ("holder", tx("Q Caron"))],
            ),
            (
                CryptoWallet,
                vec![
                    ("name", tx("Ledger")),
                    (
                        "recovery_phrase",
                        FieldValue::Mnemonic(Zeroizing::new("abandon ".repeat(11) + "about")),
                    ),
                ],
            ),
            (Subscription, vec![("service", tx("Netflix"))]),
            (Identity, vec![("first_name", tx("Quentin"))]),
            (
                IdCard,
                vec![
                    ("country", tx("FR")),
                    ("number", cn("123456789012")),
                    ("expiry", FieldValue::Date(date!(2032 - 05 - 01))),
                ],
            ),
            (
                Passport,
                vec![
                    ("issuing_country", tx("FR")),
                    ("number", cn("12AB34567")),
                    ("expiry", FieldValue::Date(date!(2032 - 05 - 01))),
                ],
            ),
            (
                DriverLicense,
                vec![
                    ("full_name", tx("Quentin Caron")),
                    ("number", cn("D1234567")),
                ],
            ),
            (
                SocialSecurityNumber,
                vec![("name", tx("Quentin Caron")), ("number", cn("078-05-1120"))],
            ),
            (MedicalRecord, vec![("patient", tx("Quentin Caron"))]),
            (
                Membership,
                vec![("organization", tx("Gym")), ("member_number", cn("M-42"))],
            ),
            (
                RewardProgram,
                vec![("company", tx("Airline")), ("member_number", cn("R-77"))],
            ),
            (
                Insurance,
                vec![("insurer", tx("AXA")), ("policy_number", cn("P-1000"))],
            ),
            (Vehicle, vec![("registration", tx("AB-123-CD"))]),
            (
                AccessCode,
                vec![
                    ("code", cn("1234A")),
                    (
                        "place",
                        FieldValue::Location(crate::model::item::Location {
                            label: "Gate".into(),
                            address: None,
                            lat: 37.4,
                            lon: -122.1,
                            radius_m: 50,
                            suggest_nearby: false,
                        }),
                    ),
                ],
            ),
            (SecureNote, vec![("content", tx("# Note"))]),
            (
                Document,
                vec![(
                    "files",
                    FieldValue::File(crate::model::field::AttachmentRef {
                        id: Id::new(),
                        name: "a.pdf".into(),
                        size: 3,
                        mime: "application/pdf".into(),
                    }),
                )],
            ),
            (
                SoftwareLicense,
                vec![("software", tx("Editor")), ("license_key", cn("AAAA-BBBB"))],
            ),
        ]
    }

    #[test]
    fn every_type_validates_once_required_fields_are_filled() {
        let rows = valid_rows();
        assert_eq!(rows.len(), 26);
        for t in ItemType::ALL {
            assert_eq!(rows.iter().filter(|(rt, _)| *rt == t).count(), 1, "{t:?}");
        }
        for (t, values) in rows {
            let mut item = new_item(t, Id::new(), "Sample");
            assert!(validate(&item).is_err(), "{t:?} empty must fail");
            let ids: Vec<&str> = values.iter().map(|(id, _)| *id).collect();
            assert_eq!(ids, req(t), "{t:?} row must cover exactly the required ids");
            for (id, value) in values {
                item.field_mut(id).unwrap().value = value;
            }
            validate(&item).unwrap_or_else(|e| panic!("{t:?}: {e}"));
        }
    }

    #[test]
    fn login_security_answer_is_concealed_and_repeatable() {
        let t = template(ItemType::Login);
        let f = |id: &str| {
            t.iter()
                .flat_map(|s| &s.fields)
                .find(|f| f.id == id)
                .unwrap()
        };
        assert!(f("security_question").repeatable);
        assert_eq!(
            f("security_answer").kind,
            crate::model::field::FieldType::Concealed
        );
        assert!(f("security_answer").repeatable);
    }

    #[test]
    fn address_kind_is_usable() {
        // Address values are accepted for Address-typed fields.
        let mut item = new_item(ItemType::Identity, Id::new(), "Me");
        item.field_mut("first_name").unwrap().value = tx("Q");
        item.field_mut("address").unwrap().value = FieldValue::Address(Address {
            line1: "1 Main St".into(),
            line2: String::new(),
            city: "Palo Alto".into(),
            postal_code: "94301".into(),
            region: "CA".into(),
            country: "US".into(),
        });
        validate(&item).unwrap();
    }
}
