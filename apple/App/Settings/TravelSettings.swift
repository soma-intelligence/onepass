import DesignKit
import LocalAuthentication
import SwiftUI
import VaultKit

/// Travel Mode (milestone 7): the vaults not marked safe for travel leave this device before a border
/// and come back after, verified against what this device saw last. iCloud keeps them meanwhile.
struct TravelSettings: View {
    @Environment(AppModel.self) private var model
    /// Opened from "Tu voyages ? > Oui": the confirmation shows at once.
    var autoConfirm = false
    @State private var status: FfiTravelStatus?
    /// Items of vaults that stay, hidden or guarded (spec 2026-11-02).
    @State private var itemPlan: FfiTravelItemPlan?
    @State private var confirmForget = false
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
                Text("settings.travel.footer")
            }
            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .accessibilityIdentifier("settings.travel.error")
                }
            }
            itemsSection
            detectionSection
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
                    Text("settings.travel.safe.footer")
                }
            }
        }
        .settingsPage("Travel Mode")
        .task {
            await reload()
            if autoConfirm, status?.active == false, !nothingLeaves { confirming = true }
        }
        .confirmationDialog(
            "Oublier les lieux appris ?", isPresented: $confirmForget, titleVisibility: .visible
        ) {
            Button("Oublier", role: .destructive) { model.travel.forgetPlaces() }
                .accessibilityIdentifier("settings.travel.forget.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("OnePass réapprendra où tu vis d'habitude.")
        }
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

    private var hiddenItems: [FfiTravelItemEntry] { itemPlan?.hidden ?? [] }
    private var guardedItems: [FfiTravelItemEntry] { itemPlan?.guarded ?? [] }

    /// Nothing would leave or be guarded: the core refuses to enter.
    private var nothingLeaves: Bool { leavingNames.isEmpty && hiddenItems.isEmpty && guardedItems.isEmpty }

    private var leavingSummary: String {
        let names = leavingNames
        var parts: [String] = []
        if !names.isEmpty {
            parts.append(String(localized: "Ces coffres quittent cet appareil jusqu'à ton retour : \(names.formatted(.list(type: .and)))."))
        }
        let hidden = hiddenItems.count
        if hidden > 0 {
            parts.append(hidden == 1
                ? String(localized: "1 élément caché part aussi.")
                : String(localized: "\(hidden) éléments cachés partent aussi."))
        }
        let guarded = guardedItems.count
        if guarded > 0 {
            parts.append(guarded == 1
                ? String(localized: "1 élément reste, protégé par mot de passe et Face ID.")
                : String(localized: "\(guarded) éléments restent, protégés par mot de passe et Face ID."))
        }
        if parts.isEmpty { return String(localized: "Rien ne quitterait cet appareil.") }
        return parts.joined(separator: " ")
    }

    /// The items marked one by one, read only here: the switches live in each item's editor.
    @ViewBuilder private var itemsSection: some View {
        if !hiddenItems.isEmpty || !guardedItems.isEmpty || (status?.hiddenItemCount ?? 0) > 0 {
            Section {
                if status?.active == true, let n = status?.hiddenItemCount, n > 0 {
                    Label(n == 1 ? String(localized: "1 élément hors de cet appareil") : String(localized: "\(n) éléments hors de cet appareil"), systemImage: "eye.slash")
                        .accessibilityIdentifier("settings.travel.hiddenItems")
                } else {
                    ForEach(hiddenItems, id: \.itemId) { entry in
                        Label { itemLabel(entry) } icon: { Image(systemName: "eye.slash") }
                    }
                }
                ForEach(guardedItems, id: \.itemId) { entry in
                    Label { itemLabel(entry) } icon: { Image(systemName: "lock.shield") }
                }
            } header: {
                Text("Éléments")
            } footer: {
                Text("Se règle dans chaque élément : Caché en voyage, ou Protection renforcée.")
            }
        }
    }

    private func itemLabel(_ entry: FfiTravelItemEntry) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(entry.title)
            Text(entry.vaultName).font(.footnote).foregroundStyle(.secondary)
        }
    }

    /// "Tu voyages ?": off by default, one line of explanation.
    private var detectionSection: some View {
        @Bindable var travel = model.travel
        return Section {
            Toggle("Proposer le Travel Mode", isOn: $travel.enabled)
                .accessibilityIdentifier("settings.travel.suggest")
            if travel.enabled || travel.usualCount > 0 {
                Button("Oublier les lieux appris", role: .destructive) { confirmForget = true }
                    .disabled(travel.usualCount == 0)
                    .accessibilityIdentifier("settings.travel.forget")
            }
        } header: {
            Text("Détection")
        } footer: {
            Text("Quand tu sembles en voyage, OnePass te le propose. Tes lieux restent sur cet appareil.")
        }
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
            .disabled(working || status == nil || nothingLeaves)
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
        if status?.active != true { itemPlan = try? await model.session.travelItemPlan() }
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
            model.travel.travelChanged(active: true)
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
            model.travel.travelChanged(active: false)
            await reload()
            model.showToast(String(localized: "De retour sur cet appareil"))
        } catch {
            errorMessage = VaultError(error).localizedMessage
            await reload()
        }
    }
}
