#if DEBUG
import Foundation
import VaultKit
#if os(iOS)
import UIKit
#endif

/// `-OnePassDemoData YES` (Debug builds only): a demonstration account in a temporary database,
/// with fictional items of the 26 types in three vaults (Personnel, Projet Atlas, Famille), a few
/// tags and favorites, one archived item and one trashed item. Master password `demo-onepass-2026`.
/// Nothing touches the real store, settings or keychain: the database lives in a fresh temporary
/// folder, the settings in their own defaults suite, the Secret Key in an in-memory keychain.
///
/// - `-OnePassDemoItem <title>`: selects that item once the data is there.
/// - `-OnePassDebugEdit YES`: also opens its editor.
/// - `-OnePassDemoLocked YES`: locks once the data is there (lock screen captures).
/// - `-OnePassDemoAccountMissing YES`: "Le compte a disparu du stockage" and its recovery actions.
/// - `-OnePassDemoAccountChanged YES`: the "Le compte iCloud a changé" banner.
/// - `-OnePassDemoLandscape YES` (iPad): asks the window scene for landscape (refused by the
///   system in the iPadOS 26 windowing modes; kept for full-screen setups).
/// - `-OnePassDemoSidebar YES` (iPad): shows the sidebar once the split view is on screen.
/// - `-OnePassSnapshot <folder>` (Mac): implies the demo data, renders the window into PNGs, quits.
enum DemoData {
    static let password = "demo-onepass-2026"
    static let displayName = "Camille Durand"
    private static let suiteName = "me.somalabs.onepass.demo"
    private static let folderPrefix = "OnePassDemo-"

    /// Settings and list order of the demo, never the real ones. Reset once per launch.
    /// `UserDefaults` is thread safe; the type is just not marked `Sendable` in this SDK.
    nonisolated(unsafe) static let defaults: UserDefaults = {
        guard let suite = UserDefaults(suiteName: suiteName) else { return .standard }
        suite.removePersistentDomain(forName: suiteName)
        return suite
    }()

    static var requested: Bool {
        UserDefaults.standard.bool(forKey: "OnePassDemoData") || snapshotFolder != nil
    }

    static var snapshotFolder: String? {
        #if os(macOS)
        UserDefaults.standard.string(forKey: "OnePassSnapshot")
        #else
        nil
        #endif
    }

    /// Where the PNGs go: the folder asked for when the sandbox lets the app write there, else
    /// `<container>/tmp/OnePassSnapshot` (`~/Library/Containers/me.somalabs.onepass/Data/tmp/...`).
    static var snapshotOutput: URL? {
        guard let folder = snapshotFolder else { return nil }
        let manager = FileManager.default
        let asked = URL(fileURLWithPath: folder, isDirectory: true)
        try? manager.createDirectory(at: asked, withIntermediateDirectories: true)
        if manager.isWritableFile(atPath: asked.path) { return asked }
        let fallback = manager.temporaryDirectory.appendingPathComponent("OnePassSnapshot", isDirectory: true)
        try? manager.createDirectory(at: fallback, withIntermediateDirectories: true)
        return fallback
    }

    /// A fresh temporary store each launch; folders of previous runs are removed first.
    static func environment() -> VaultEnvironment {
        let manager = FileManager.default
        let tmp = manager.temporaryDirectory
        // Only demo stores older than a day: another demo run may still be using a recent one.
        let dayAgo = Date().addingTimeInterval(-86_400)
        for name in (try? manager.contentsOfDirectory(atPath: tmp.path)) ?? [] where name.hasPrefix(folderPrefix) {
            let url = tmp.appendingPathComponent(name, isDirectory: true)
            let created = (try? manager.attributesOfItem(atPath: url.path)[.creationDate]) as? Date
            if let created, created < dayAgo { try? manager.removeItem(at: url) }
        }
        let folder = tmp.appendingPathComponent(folderPrefix + UUID().uuidString, isDirectory: true)
        try? manager.createDirectory(at: folder, withIntermediateDirectories: true)

        let defaults = Self.defaults
        // Fictional sites: no network request for their icons.
        defaults.set(false, forKey: "onepass.siteIconsEnabled")
        // `-OnePassDemoAccountMissing YES`: the settings name an account the empty store lacks, which
        // is how "Le compte a disparu du stockage" shows (no seeding then).
        if UserDefaults.standard.bool(forKey: "OnePassDemoAccountMissing") {
            defaults.set("0192f3a4b5c6d7e8f9a0b1c2d3e4f5a6", forKey: "onepass.accountID")
            defaults.set(displayName, forKey: "onepass.displayName")
        }
        let keychain = InMemoryKeychain()
        let clock = SystemClock()
        return VaultEnvironment(
            databaseURL: folder.appendingPathComponent("vault.sqlite"),
            keychain: keychain,
            biometrics: BiometricUnlock(keyring: SecureEnclaveKeyring(accessGroup: nil), keychain: keychain, clock: clock),
            settings: VaultSettings(defaults: defaults),
            sync: NoSync(),
            clock: clock,
            pasteboard: SystemPasteboard(),
            // Never the system identity store: the demo's fictional Logins stay out of QuickType.
            // Off at launch, so the AutoFill tip card shows; "Activer" turns it on in memory.
            identityStore: InMemoryIdentityStore(enabled: false))
    }
}

/// Progress lines for the snapshot run (no value of any field), in `<folder>/trace.txt`.
enum DemoTrace {
    static func log(_ format: String, _ args: any CVarArg...) {
        guard let folder = DemoData.snapshotOutput else { return }
        let line = String(format: format, arguments: args) + "\n"
        let url = folder.appendingPathComponent("trace.txt")
        if let handle = try? FileHandle(forWritingTo: url) {
            handle.seekToEndOfFile()
            handle.write(Data(line.utf8))
            try? handle.close()
        } else {
            try? Data(line.utf8).write(to: url)
        }
    }
}

extension AppModel {
    func seedDemoData() {
        DemoTrace.log("demo: state %@", String(describing: session.state))
        guard session.state == .noAccount else { return }
        let defaults = UserDefaults.standard
        Task {
            do {
                _ = try await session.createAccount(
                    password: DemoData.password, displayName: DemoData.displayName, mode: .personal)
                onboardingInProgress = false
                DemoTrace.log("demo: account created")
                try await DemoSeeder(session: session).run()
                DemoTrace.log("demo: %d items", session.summaries.count)
                if let title = defaults.string(forKey: "OnePassDemoItem"),
                    let summary = session.summaries.first(where: { $0.title == title })
                {
                    selectedItem = ItemRef(vaultID: summary.vaultId, itemID: summary.id)
                    editing = defaults.bool(forKey: "OnePassDebugEdit")
                }
                if defaults.bool(forKey: "OnePassDemoLocked") { lock() }
                // `-OnePassDemoAccountChanged YES`: the "Le compte iCloud a changé" banner.
                if defaults.bool(forKey: "OnePassDemoAccountChanged") { debugSetSyncStatus(.accountChanged) }
                #if os(iOS) || os(visionOS)
                // Screenshots: `-OnePassDemoSettings YES [-OnePassDemoSettingsPage security]`.
                showSettings = defaults.bool(forKey: "OnePassDemoSettings")
                #endif
                #if os(iOS)
                if defaults.bool(forKey: "OnePassDemoLandscape") {
                    for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
                        scene.requestGeometryUpdate(.iOS(interfaceOrientations: .landscapeLeft)) { error in
                            NSLog("OnePassDemo rotation refused: %@", error.localizedDescription)
                        }
                    }
                }
                #endif
                #if os(macOS)
                if let folder = DemoData.snapshotOutput { await Snapshot.run(model: self, directory: folder) }
                #endif
            } catch {
                DemoTrace.log("demo: seeding failed: %@", String(describing: VaultError(error)))
                onboardingInProgress = false
            }
        }
    }
}

/// Writes the fictional items. Every value is made up (`exemple.fr`, Camille Durand, Projet Atlas).
@MainActor
private struct DemoSeeder {
    let session: VaultSession

    func run() async throws {
        guard let personal = session.vaults.first?.id else { return }
        try await session.createVault(
            FfiVaultMeta(name: "Projet Atlas", icon: "briefcase", color: "teal", travelSafe: false, mcpAccess: false))
        try await session.createVault(
            FfiVaultMeta(name: "Famille", icon: "house", color: "orange", travelSafe: false, mcpAccess: false))
        let atlas = vaultID("Projet Atlas") ?? personal
        let family = vaultID("Famille") ?? personal

        // Access.
        let forge = try await add(.login, "Forge Atlas", atlas, [
            "username": .text(value: "camille.durand@exemple.fr"),
            "password": .password(value: "tj7N-qe4L-wPz9-Kc2m"),
            "totp": .otp(value: "JBSWY3DPEHPK3PXP"),
        ], urls: ["https://forge.exemple.fr"], tags: ["Travail"], favorite: true,
            notes: "Compte **principal** du projet.")
        try await add(.password, "Coffre du bureau Atlas", atlas, [
            "password": .password(value: "Orage-Comete-Tapis-58"),
            "context": .text(value: "Armoire forte, 2e étage"),
        ], tags: ["Travail"])
        try await add(.email, "Messagerie Exemple", personal, [
            "address": .email(value: "camille.durand@exemple.fr"),
            "password": .password(value: "Ruisseau-Lampe-Vent-17"),
            "provider": .text(value: "Messagerie Exemple"),
            "incoming_server": .text(value: "imap.exemple.fr"),
        ], urls: ["https://mail.exemple.fr"], favorite: true)
        try await add(.server, "Serveur de build Atlas", atlas, [
            "host": .text(value: "build.atlas.exemple.fr"),
            "port": .number(value: 22),
            "username": .text(value: "deploy"),
            "password": .password(value: "Granit-Neige-Fleuve-31"),
        ], tags: ["Travail"])
        try await add(.database, "Base clients Atlas", atlas, [
            "engine": .menu(value: "PostgreSQL"),
            "host": .text(value: "db.atlas.exemple.fr"),
            "port": .number(value: 5432),
            "database": .text(value: "clients"),
            "username": .text(value: "atlas_app"),
            "password": .password(value: "Sable-Orme-Brume-64"),
        ])
        try await add(.router, "Wi-Fi Maison", family, [
            "ssid": .text(value: "Maison-Durand"),
            "wifi_password": .password(value: "Prairie-Soleil-Nuage-90"),
            "security": .menu(value: "WPA3"),
        ], tags: ["Famille"], favorite: true)
        try await add(.apiCredential, "API Cartes Atlas", atlas, [
            "service": .text(value: "Cartes Exemple"),
            "key": .concealed(value: "ex_test_4f9c2b7a1d8e6f3a"),
            "base_url": .url(value: "https://api.cartes.exemple.fr"),
        ], tags: ["Travail"])
        try await add(.sshKey, "Clé de déploiement Atlas", atlas, [
            "private_key": .sshKey(value: FfiSshKey(
                privatePem: "-----BEGIN OPENSSH PRIVATE KEY-----\nexemple-fictif-non-utilisable\n-----END OPENSSH PRIVATE KEY-----",
                publicOpenssh: "", fingerprintSha256: "")),
            "comment": .text(value: "deploy@atlas.exemple.fr"),
        ])

        // Finance.
        let card = try await add(.creditCard, "Carte Visa Exemple", personal, [
            "cardholder": .text(value: "CAMILLE DURAND"),
            "number": .concealed(value: "4111 1111 1111 1111"),
            "expiry": .monthYear(year: 2030, month: 3),
            "cvv": .concealed(value: "123"),
            "issuer": .text(value: "Banque Exemple"),
        ], tags: ["Finance"], favorite: true)
        try await add(.bankAccount, "Compte courant", personal, [
            "bank": .text(value: "Banque Exemple"),
            "holder": .text(value: "Camille Durand"),
            "iban": .text(value: "FR76 3000 6000 0112 3456 7890 189"),
        ], tags: ["Finance"])
        try await add(.cryptoWallet, "Portefeuille de test", personal, [
            "name": .text(value: "Portefeuille de test"),
            "recovery_phrase": .mnemonic(value: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
        ], tags: ["Finance"])
        try await add(.subscription, "Musique Exemple", family, [
            "service": .text(value: "Musique Exemple"),
            "price": .money(minorUnits: 1099, currency: "EUR"),
            "frequency": .menu(value: "Mensuel"),
            "payment_method": .itemLink(itemId: card.id),
        ], tags: ["Famille"])

        // Identity.
        try await add(.identity, "Camille Durand", personal, [
            "first_name": .text(value: "Camille"),
            "last_name": .text(value: "Durand"),
            "email": .email(value: "camille.durand@exemple.fr"),
            "mobile_phone": .phone(value: "+33 6 00 00 00 00"),
        ], favorite: true)
        try await add(.idCard, "Carte d'identité", personal, [
            "country": .text(value: "France"),
            "number": .concealed(value: "X4RTBPFW4"),
            "expiry": .date(value: FfiDate(year: 2031, month: 5, day: 12)),
            "last_name": .text(value: "Durand"),
            "first_names": .text(value: "Camille"),
        ])
        try await add(.passport, "Passeport", personal, [
            "issuing_country": .text(value: "France"),
            "number": .concealed(value: "22AB12345"),
            "expiry": .date(value: FfiDate(year: 2032, month: 9, day: 1)),
        ], tags: ["Voyage"])
        try await add(.driverLicense, "Permis de conduire", personal, [
            "full_name": .text(value: "Camille Durand"),
            "number": .concealed(value: "120675400123"),
            "categories": .text(value: "B"),
        ])
        try await add(.socialSecurityNumber, "Sécurité sociale", personal, [
            "name": .text(value: "Camille Durand"),
            "number": .concealed(value: "2 55 08 14 168 025 38"),
            "country": .text(value: "FR"),
        ])
        try await add(.medicalRecord, "Dossier médical", family, [
            "patient": .text(value: "Camille Durand"),
            "blood_type": .menu(value: "O+"),
            "doctor_name": .text(value: "Dr Exemple"),
        ], tags: ["Famille"])
        try await add(.membership, "Club de randonnée Exemple", family, [
            "organization": .text(value: "Club de randonnée Exemple"),
            "member_number": .concealed(value: "RANDO-0042"),
            "member_name": .text(value: "Camille Durand"),
        ])
        try await add(.rewardProgram, "Carte Fidélité Exemple", personal, [
            "company": .text(value: "Exemple Market"),
            "member_number": .concealed(value: "EX-2026-0042"),
            "points_balance": .number(value: 1250),
            "barcode": .barcode(value: "EX20260042", format: .code128),
        ], tags: ["Voyage"])

        // Property and contracts.
        try await add(.insurance, "Assurance habitation", family, [
            "insurer": .text(value: "Assurances Exemple"),
            "policy_number": .concealed(value: "HAB-2026-1187"),
            "insurance_type": .menu(value: "Habitation"),
        ], tags: ["Famille"])
        try await add(.vehicle, "Voiture familiale", family, [
            "registration": .text(value: "AB-123-CD"),
            "make": .text(value: "Marque Exemple"),
            "model": .text(value: "Citadine"),
            "year": .number(value: 2022),
        ], tags: ["Famille"])
        try await add(.accessCode, "Digicode immeuble", family, [
            "code": .concealed(value: "4821B"),
            "place": .location(value: FfiLocation(
                label: "Immeuble", address: "12 rue de l'Exemple, Paris", lat: 48.85661, lon: 2.35222,
                radiusM: 100, suggestNearby: false)),
        ])

        // Others.
        try await add(.secureNote, "Codes du portail", family, [
            "content": .text(value: "Portail : 4821\nGarage : 1937"),
        ])
        try await add(.document, "Notice de la chaudière", family, [
            "issuer": .text(value: "Chauffage Exemple"),
            "document_date": .date(value: FfiDate(year: 2025, month: 11, day: 4)),
        ])
        try await add(.softwareLicense, "Éditeur Exemple Pro", atlas, [
            "software": .text(value: "Éditeur Exemple Pro"),
            "license_key": .concealed(value: "EXPL-4F2K-9QZ7-ATLS"),
            "seats": .number(value: 5),
        ], tags: ["Travail"])

        // One archived item, one in Supprimés récemment.
        let old = try await add(.login, "Ancien forum Exemple", personal, [
            "username": .text(value: "camille.d"),
            "password": .password(value: "Vieux-Mot-De-Passe-12"),
        ], urls: ["https://forum.exemple.fr"])
        try await session.archive(itemID: old.id, vaultID: old.vaultId)
        let draft = try await add(.secureNote, "Brouillon à jeter", personal, [
            "content": .text(value: "Liste de courses fictive."),
        ])
        try await session.trash(itemID: draft.id, vaultID: draft.vaultId)
        _ = forge
    }

    private func vaultID(_ name: String) -> String? {
        session.vaults.first { $0.meta.name == name }?.id
    }

    @discardableResult
    private func add(
        _ type: FfiItemType, _ title: String, _ vaultID: String, _ values: [String: FfiFieldValue],
        urls: [String] = [], tags: [String] = [], favorite: Bool = false, notes: String = ""
    ) async throws -> FfiItem {
        var item = try session.newItem(type: type, vaultID: vaultID)
        item.title = title
        for (id, value) in values { item.set(id, value) }
        item.urls = urls.enumerated().map { FfiUrl(label: "", url: $1, rule: .domain, primary: $0 == 0) }
        item.tags = tags
        item.favorite = favorite
        item.notes = notes
        return try await session.save(ItemDraft(item: item).preparedForSave())
    }
}
#endif
