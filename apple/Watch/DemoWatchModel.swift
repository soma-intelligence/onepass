#if DEBUG
    import CompanionLink
    import Foundation
    import Observation
    import OnePassCore

    /// Fictional entries for screenshots (`-OnePassWatchDemo YES`). Codes come from fixed fake
    /// seeds through the core, nothing is stored.
    @MainActor
    @Observable
    final class DemoWatchModel: WatchEntriesModel {
        let entries: [FfiCompanionEntry]
        let state: WatchVaultState = .ready

        /// Fake RFC 4648 seed, demo only.
        private let seeds = ["demo-forge-atlas": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"]

        init() {
            entries = [
                FfiCompanionEntry(
                    itemId: "demo-forge-atlas", vaultId: "demo", itemType: .login,
                    title: "Forge Atlas", subtitle: "camille.durand@exemple.fr", hasTotp: true,
                    fields: [
                        FfiCompanionField(
                            label: "Identifiant", value: "camille.durand@exemple.fr", kind: .text)
                    ]),
                FfiCompanionEntry(
                    itemId: "demo-wifi", vaultId: "demo", itemType: .router,
                    title: "Wi-Fi Maison", subtitle: "Maison-Durand", hasTotp: false,
                    fields: [
                        FfiCompanionField(label: "Réseau", value: "Maison-Durand", kind: .text),
                        FfiCompanionField(
                            label: "Mot de passe", value: "tulipe-orage-42", kind: .concealed),
                    ]),
                FfiCompanionEntry(
                    itemId: "demo-library", vaultId: "demo", itemType: .membership,
                    title: "Carte Bibliothèque", subtitle: "Camille Durand", hasTotp: false,
                    fields: [
                        FfiCompanionField(label: "Numéro de membre", value: "BM-204817", kind: .text),
                        FfiCompanionField(
                            label: "Code-barres", value: "2048170093",
                            kind: .barcode(format: .code128)),
                    ]),
                FfiCompanionEntry(
                    itemId: "demo-bank", vaultId: "demo", itemType: .creditCard,
                    title: "Banque Exemple", subtitle: "•••• 7890", hasTotp: false,
                    fields: [
                        FfiCompanionField(label: "Titulaire", value: "Camille Durand", kind: .text),
                        FfiCompanionField(label: "Numéro", value: "•••• 7890", kind: .text),
                    ]),
            ]
        }

        func code(for itemID: String, at date: Date) -> FfiTotpCode? {
            guard let seed = seeds[itemID] else { return nil }
            return try? totpNow(
                secretOrUri: seed, unixSeconds: UInt64(max(0, date.timeIntervalSince1970)))
        }
    }
#endif
