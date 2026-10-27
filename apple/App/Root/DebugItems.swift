#if DEBUG
import Foundation
import VaultKit

/// Screenshots and manual checks, Debug builds only. Fictional data only, in the isolated test
/// store (`TestIsolation` is forced by `-OnePassDebugItem` and `-OnePassDebugNewItem`).
///
/// - `-OnePassDebugItem login|card|note|reward`: unlocks the fictional account (created when
///   missing), adds a few fictional items once, and opens the chosen one.
/// - `-OnePassDebugEdit YES`: also opens its editor.
/// - `-OnePassDebugNewItem login|card|...`: opens the editor of a new item of that type instead.
/// - `-OnePassDebugEditorError YES` with `-OnePassDebugNewItem`: fills a title only, so a save
///   shows the validation error under the first required field.
/// - `-OnePassDebugAutoSave YES`: the editor presses Enregistrer once it is shown.
/// - `-OnePassDebugGenerator YES`: the first password field opens the generator.
extension AppModel {
    static let debugPassword = "ruisseau-tapis-orage-comete"

    func openDebugItemIfRequested() {
        let defaults = UserDefaults.standard
        let wanted = defaults.string(forKey: "OnePassDebugItem")
        let newType = defaults.string(forKey: "OnePassDebugNewItem")
        guard wanted != nil || newType != nil else { return }
        Task {
            do {
                try await debugUnlock()
                let titles = try await debugSeed()
                if let newType, let type = Self.debugType(newType) {
                    guard let vault = session.vaults.first else { return }
                    var item = try session.newItem(type: type, vaultID: vault.id)
                    if defaults.bool(forKey: "OnePassDebugEditorError") { item.title = "Compte fictif" }
                    if type == .accessCode {
                        item.title = "Bureau Atlas"
                        item.set("place", .location(value: FfiLocation(
                            label: "Bureau Atlas", address: "12 rue de l'Exemple, Paris", lat: 48.85661,
                            lon: 2.35222, radiusM: 100, suggestNearby: false)))
                    }
                    newItemDraft = ItemDraft(item: item)
                } else if let wanted, let title = titles[wanted],
                    let summary = session.summaries.first(where: { $0.title == title })
                {
                    selectedItem = ItemRef(vaultID: summary.vaultId, itemID: summary.id)
                    editing = defaults.bool(forKey: "OnePassDebugEdit")
                }
            } catch {
                // Debug helper: nothing to show, the normal screens stay.
            }
        }
    }

    private static func debugType(_ name: String) -> FfiItemType? {
        switch name {
        case "login": .login
        case "card": .creditCard
        case "note": .secureNote
        case "reward": .rewardProgram
        case "server": .server
        case "identity": .identity
        case "access": .accessCode
        default: nil
        }
    }

    private func debugUnlock() async throws {
        switch session.state {
        case .noAccount:
            _ = try await session.createAccount(
                password: Self.debugPassword, displayName: "Camille Durand", mode: .personal)
            onboardingInProgress = false
        case .locked:
            try await session.unlock(password: Self.debugPassword)
            onboardingInProgress = false
        default:
            break
        }
    }

    /// Adds the fictional items once; returns the title of each debug key.
    private func debugSeed() async throws -> [String: String] {
        let titles = [
            "login": "Forge Atlas", "card": "Carte Projet Atlas", "note": "Codes du portail",
            "reward": "Carte Fidélité Exemple",
        ]
        guard session.summaries.isEmpty, let personal = session.vaults.first else { return titles }
        try await session.createVault(
            FfiVaultMeta(name: "Projet Atlas", icon: "briefcase", color: "teal", travelSafe: false, mcpAccess: false))

        var login = try session.newItem(type: .login, vaultID: personal.id)
        login.title = "Forge Atlas"
        login.set("username", .text(value: "camille.durand@exemple.fr"))
        login.set("password", .password(value: "Ancien-mot-de-passe-42"))
        login.set("totp", .otp(value: "JBSWY3DPEHPK3PXP"))
        login.urls = [FfiUrl(label: "", url: "https://forge.exemple.fr", rule: .domain, primary: true)]
        login.tags = ["Travail", "Projet Atlas"]
        login.favorite = true
        login.notes = "Compte **principal** du projet.\nVoir [la documentation](https://doc.exemple.fr) avant de modifier les accès."
        login = try await session.save(login)
        // A second save replaces the password: one previous version in the history.
        login.set("password", .password(value: "tj7N-qe4L-wPz9-Kc2m"))
        login = try await session.save(login)

        var card = try session.newItem(type: .creditCard, vaultID: personal.id)
        card.title = "Carte Projet Atlas"
        card.set("cardholder", .text(value: "CAMILLE DURAND"))
        card.set("number", .concealed(value: "4111 1111 1111 1111"))
        card.set("expiry", .monthYear(year: 2030, month: 3))
        card.set("cvv", .concealed(value: "123"))
        card.set("limit", .money(minorUnits: 250_000, currency: "EUR"))
        card.set("issuer", .text(value: "Banque Exemple"))
        _ = try await session.save(card)

        var note = try session.newItem(type: .secureNote, vaultID: personal.id)
        note.title = "Codes du portail"
        note.set("content", .text(value: "Portail : 4821\nGarage : 1937"))
        note.reprompt = true
        _ = try await session.save(note)

        var reward = try session.newItem(type: .rewardProgram, vaultID: personal.id)
        reward.title = "Carte Fidélité Exemple"
        reward.set("company", .text(value: "Exemple Market"))
        reward.set("member_number", .concealed(value: "EX-2026-0042"))
        reward.set("points_balance", .number(value: 1250))
        reward.set("barcode", .barcode(value: "EX20260042", format: .code128))
        reward.set("online_account", .itemLink(itemId: login.id))
        _ = try await session.save(reward)
        return titles
    }
}

extension FfiItem {
    /// First field with this id, any section.
    mutating func set(_ fieldID: String, _ value: FfiFieldValue) {
        for s in sections.indices {
            if let f = sections[s].fields.firstIndex(where: { $0.id == fieldID }) {
                sections[s].fields[f].value = value
                return
            }
        }
    }
}
#endif
