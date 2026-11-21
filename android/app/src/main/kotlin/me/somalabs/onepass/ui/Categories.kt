package me.somalabs.onepass.ui

import android.content.Context
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiItemType

/**
 * The 26 item types as the iPhone shows them (DesignKit `ItemCategory`): the
 * same order, the same rendered tile (`category-<type>` of the app's assets,
 * imported by scripts/import-apple-assets.ps1), the same singular and plural
 * names in French and English (DesignKit's string catalog).
 */
data class Category(
    val type: FfiItemType,
    val art: Int,
    val singularFr: String,
    val singularEn: String,
    val pluralFr: String,
    val pluralEn: String,
    val hex: Int,
) {
    fun singular(c: Context) = if (french(c)) singularFr else singularEn
    fun plural(c: Context) = if (french(c)) pluralFr else pluralEn

    companion object {
        fun french(c: Context) = c.resources.configuration.locales[0].language == "fr"

        val ALL: List<Category> = listOf(
            Category(FfiItemType.LOGIN, R.drawable.cat_login, "Connexion", "Login", "Connexions", "Logins", 0x0E9F9F),
            Category(FfiItemType.PASSWORD, R.drawable.cat_password, "Mot de passe", "Password", "Mots de passe", "Passwords", 0x0F5E63),
            Category(FfiItemType.EMAIL, R.drawable.cat_email, "Compte email", "Email account", "Comptes email", "Email accounts", 0xBE185D),
            Category(FfiItemType.SERVER, R.drawable.cat_server, "Serveur", "Server", "Serveurs", "Servers", 0x5B6472),
            Category(FfiItemType.DATABASE, R.drawable.cat_database, "Base de données", "Database", "Bases de données", "Databases", 0x5B6472),
            Category(FfiItemType.ROUTER, R.drawable.cat_router, "Routeur Wi-Fi", "Wi-Fi router", "Routeurs Wi-Fi", "Wi-Fi routers", 0x0F766E),
            Category(FfiItemType.API_CREDENTIAL, R.drawable.cat_api_credential, "Identifiant d'API", "API credential", "Identifiants API", "API credentials", 0x0891B2),
            Category(FfiItemType.SSH_KEY, R.drawable.cat_ssh_key, "Clé SSH", "SSH key", "Clés SSH", "SSH keys", 0x475569),
            Category(FfiItemType.CREDIT_CARD, R.drawable.cat_credit_card, "Carte bancaire", "Credit card", "Cartes bancaires", "Credit cards", 0x2F80ED),
            Category(FfiItemType.BANK_ACCOUNT, R.drawable.cat_bank_account, "Compte bancaire", "Bank account", "Comptes bancaires", "Bank accounts", 0xE08A00),
            Category(FfiItemType.CRYPTO_WALLET, R.drawable.cat_crypto_wallet, "Portefeuille crypto", "Crypto wallet", "Portefeuilles crypto", "Crypto wallets", 0x2563EB),
            Category(FfiItemType.SUBSCRIPTION, R.drawable.cat_subscription, "Abonnement", "Subscription", "Abonnements", "Subscriptions", 0x9333EA),
            Category(FfiItemType.IDENTITY, R.drawable.cat_identity, "Identité", "Identity", "Identités", "Identities", 0x22A06B),
            Category(FfiItemType.ID_CARD, R.drawable.cat_id_card, "Carte d'identité", "ID card", "Cartes d'identité", "ID cards", 0x15803D),
            Category(FfiItemType.PASSPORT, R.drawable.cat_passport, "Passeport", "Passport", "Passeports", "Passports", 0x1D4ED8),
            Category(FfiItemType.DRIVER_LICENSE, R.drawable.cat_driver_license, "Permis de conduire", "Driver's license", "Permis de conduire", "Driver's licenses", 0xE11D48),
            Category(FfiItemType.SOCIAL_SECURITY_NUMBER, R.drawable.cat_social_security_number, "Numéro de sécurité sociale", "Social Security number", "Numéros de sécu", "Social Security numbers", 0x1E40AF),
            Category(FfiItemType.MEDICAL_RECORD, R.drawable.cat_medical_record, "Dossier médical", "Medical record", "Dossiers médicaux", "Medical records", 0xDC2626),
            Category(FfiItemType.MEMBERSHIP, R.drawable.cat_membership, "Adhésion", "Membership", "Cartes de membre", "Memberships", 0x7C3AED),
            Category(FfiItemType.REWARD_PROGRAM, R.drawable.cat_reward_program, "Programme de fidélité", "Reward program", "Programmes de fidélité", "Reward programs", 0xDB2777),
            Category(FfiItemType.INSURANCE, R.drawable.cat_insurance, "Assurance", "Insurance", "Assurances", "Insurance", 0x0D9488),
            Category(FfiItemType.VEHICLE, R.drawable.cat_vehicle, "Véhicule", "Vehicle", "Véhicules", "Vehicles", 0x475569),
            Category(FfiItemType.ACCESS_CODE, R.drawable.cat_access_code, "Code d'accès", "Access code", "Digicodes", "Access codes", 0x4338CA),
            Category(FfiItemType.SECURE_NOTE, R.drawable.cat_secure_note, "Note sécurisée", "Secure note", "Notes sécurisées", "Secure notes", 0xD99A1E),
            Category(FfiItemType.DOCUMENT, R.drawable.cat_document, "Document", "Document", "Documents", "Documents", 0x3478F6),
            Category(FfiItemType.SOFTWARE_LICENSE, R.drawable.cat_software_license, "Licence logicielle", "Software license", "Licences logicielles", "Software licenses", 0x2563EB),
        )

        private val byType = ALL.associateBy { it.type }

        fun of(t: FfiItemType): Category = byType.getValue(t)
    }
}
