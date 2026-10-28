import DesignKit
import LocalAuthentication
import SwiftUI
import VaultKit

/// Travel Mode (milestone 7): the vaults not marked safe for travel leave this device before a border
/// and come back after, verified against what this device saw last. iCloud keeps them meanwhile.
struct TravelSettings: View {
    @Environment(AppModel.self) private var model
    @State private var status: FfiTravelStatus?
    @State private var working = false
    @State private var confirming = false
    @State private var errorMessage: String?

    var body: some View {
        Form {
            Section {
                statusRow
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("settings.travel.status")
                actionButton
            } footer: {
                Text("Les coffres qui partent restent dans iCloud : rien n'est supprimé. Au retour, OnePass les vérifie avant de les rouvrir.")
            }
            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .accessibilityIdentifier("settings.travel.error")
                }
            }
            if status?.active != true {
                Section {
                    ForEach(model.session.allVaults, id: \.id) { vault in
                        Toggle(isOn: safeBinding(vault)) {
                            HStack(spacing: 12) {
                                VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: 28)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(vault.meta.name)
                                    Text(vault.meta.travelSafe ? "Reste sur l'appareil" : "Quitte l'appareil")
                                        .font(.footnote)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .disabled(working)
                        .accessibilityIdentifier("settings.travel.safe.\(vault.id)")
                    }
                } header: {
                    Text("Sûr en voyage")
                } footer: {
                    Text("Ce réglage suit le coffre sur tous tes appareils.")
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Travel Mode")
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .task { await reload() }
        .confirmationDialog(
            "Activer le Travel Mode ?", isPresented: $confirming, titleVisibility: .visible
        ) {
            Button("Activer") { Task { await enter() } }
                .accessibilityIdentifier("settings.travel.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text(leavingSummary)
        }
    }

    private var leavingNames: [String] {
        model.session.allVaults.filter { !$0.meta.travelSafe }.map(\.meta.name)
    }

    private var leavingSummary: String {
        let names = leavingNames
        if names.isEmpty { return String(localized: "Aucun coffre ne quitterait cet appareil.") }
        return String(localized: "Ces coffres quittent cet appareil jusqu'à ton retour : \(names.formatted(.list(type: .and))).")
    }

    @ViewBuilder private var statusRow: some View {
        if let status, status.active {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(status.exiting ? "Retour en cours" : "Travel Mode activé")
                    if let at = status.enteredAt {
                        Text("Depuis le \(Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .abbreviated, time: .shortened)), \(Self.vaultCount(status.hiddenCount)) hors de cet appareil")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            } icon: {
                Image(systemName: "airplane").foregroundStyle(Theme.accent)
            }
        } else {
            Label("Travel Mode désactivé", systemImage: "airplane")
                .foregroundStyle(.secondary)
        }
    }

    static func vaultCount(_ n: UInt32) -> String {
        n == 1 ? String(localized: "1 coffre") : String(localized: "\(n) coffres")
    }

    @ViewBuilder private var actionButton: some View {
        if status?.active == true {
            Button {
                Task { await exit() }
            } label: {
                HStack {
                    Text(status?.exiting == true ? "Terminer le retour" : "Désactiver le Travel Mode")
                    if working { Spacer(); ProgressView().controlSize(.small) }
                }
            }
            .disabled(working)
            .accessibilityIdentifier("settings.travel.exit")
        } else {
            Button {
                errorMessage = nil
                confirming = true
            } label: {
                HStack {
                    Text("Activer le Travel Mode")
                    if working { Spacer(); ProgressView().controlSize(.small) }
                }
            }
            .disabled(working || status == nil || leavingNames.isEmpty)
            .accessibilityIdentifier("settings.travel.enter")
        }
    }

    private func safeBinding(_ vault: FfiVault) -> Binding<Bool> {
        Binding {
            vault.meta.travelSafe
        } set: { safe in
            var meta = vault.meta
            meta.travelSafe = safe
            Task {
                do {
                    try await model.session.updateVault(id: vault.id, meta: meta)
                } catch {
                    errorMessage = VaultError(error).localizedMessage
                }
            }
        }
    }

    private func reload() async {
        status = try? await model.session.travelStatus()
    }

    private func enter() async {
        working = true
        defer { working = false }
        errorMessage = nil
        // The device owner confirms (Touch ID, Face ID or the passcode). A device without any owner
        // authentication has nothing to check: hiding vaults is never a risk in itself.
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
            guard await SystemPresenceChecker().confirm(prompt: String(localized: "Activer le Travel Mode")) else { return }
        }
        // Every write of the leaving vaults must be in iCloud first: the core refuses otherwise.
        await model.coordinator?.syncNow()
        do {
            status = try await model.session.enterTravel()
            model.showToast(String(localized: "Travel Mode activé"))
        } catch {
            errorMessage = VaultError(error).localizedMessage
            await reload()
        }
    }

    private func exit() async {
        working = true
        defer { working = false }
        errorMessage = nil
        do {
            try await model.session.beginTravelExit()
            // The vaults come back from iCloud, then the core checks them.
            await model.coordinator?.refetchFromScratch()
            status = try await model.session.finishTravelExit()
            model.showToast(String(localized: "Coffres de retour sur cet appareil"))
        } catch {
            errorMessage = VaultError(error).localizedMessage
            await reload()
        }
    }
}
