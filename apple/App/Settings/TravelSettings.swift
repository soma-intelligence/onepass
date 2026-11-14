import DesignKit
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
    /// The personal vaults (the core's travel plan): shared vaults stay out of Travel Mode.
    @State private var personalVaultIDs: Set<String>?
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
            tripsSection
            detectionSection
            if status?.active != true {
                Section {
                    ForEach(travelVaults, id: \.id) { vault in
                        Toggle(isOn: safeBinding(vault)) {
                            HStack(spacing: Theme.Space.m) {
                                VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: 28)
                                VStack(alignment: .leading, spacing: Theme.Space.xxs) {
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
                    Text("app.safeForTravel")
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
            "settings.travel.forget.title", isPresented: $confirmForget, titleVisibility: .visible
        ) {
            Button("settings.forget", role: .destructive) { model.travel.forgetPlaces() }
                .accessibilityIdentifier("settings.travel.forget.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("settings.travel.forget.message")
        }
        .confirmationDialog(
            "Activer le Travel Mode ?", isPresented: $confirming, titleVisibility: .visible
        ) {
            Button("app.turnOn") { Task { await enter() } }
                .accessibilityIdentifier("settings.travel.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text(leavingSummary)
        }
    }

    private var leavingNames: [String] {
        travelVaults.filter { !$0.meta.travelSafe }.map(\.meta.name)
    }

    private var hiddenItems: [FfiTravelItemEntry] { itemPlan?.hidden ?? [] }
    private var guardedItems: [FfiTravelItemEntry] { itemPlan?.guarded ?? [] }

    /// Nothing would leave or be guarded: the core refuses to enter.
    private var nothingLeaves: Bool { leavingNames.isEmpty && hiddenItems.isEmpty && guardedItems.isEmpty }

    private var leavingSummary: String {
        let names = leavingNames
        var parts: [String] = []
        if !names.isEmpty {
            parts.append(String(localized: "settings.theseVaultsLeaveDevice \(names.formatted(.list(type: .and)))"))
        }
        let hidden = hiddenItems.count
        if hidden > 0 {
            parts.append(String(localized: "settings.travel.leaving.hiddenItems \(hidden)"))
        }
        let guarded = guardedItems.count
        if guarded > 0 {
            parts.append(String(localized: "settings.travel.leaving.guardedItems \(guarded)"))
        }
        if parts.isEmpty { return String(localized: "settings.travel.leaving.nothing") }
        return parts.joined(separator: " ")
    }

    /// The items marked one by one, read only here: the switches live in each item's editor.
    @ViewBuilder private var itemsSection: some View {
        if !hiddenItems.isEmpty || !guardedItems.isEmpty || (status?.hiddenItemCount ?? 0) > 0 {
            Section {
                if status?.active == true, let n = status?.hiddenItemCount, n > 0 {
                    Label(String(localized: "settings.travel.hiddenItems \(Int(n))"), systemImage: "eye.slash")
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
                Text("settings.travel.items.footer")
            }
        }
    }

    private func itemLabel(_ entry: FfiTravelItemEntry) -> some View {
        VStack(alignment: .leading, spacing: Theme.Space.xxs) {
            Text(entry.title)
            Text(entry.vaultName).font(.footnote).foregroundStyle(.secondary)
        }
    }

    /// Planned trips: a reminder the eve and 3 hours before, and optionally Travel Mode on its own.
    private var tripsSection: some View {
        let trips = model.travel.trips.sorted { $0.start < $1.start }
        return Section {
            ForEach(trips) { trip in
                NavigationLink {
                    TravelTripEditor(trip: trip)
                } label: {
                    tripRow(trip)
                }
                .accessibilityIdentifier("settings.travel.trip.\(trip.id.uuidString)")
                .contextMenu {
                    Button("common.delete", role: .destructive) { model.travel.deleteTrip(id: trip.id) }
                }
            }
            .onDelete { offsets in
                for index in offsets { model.travel.deleteTrip(id: trips[index].id) }
            }
            NavigationLink {
                TravelTripEditor(trip: nil)
            } label: {
                Label("settings.travel.addTrip", systemImage: "plus")
            }
            .accessibilityIdentifier("settings.travel.addTrip")
        } header: {
            Text("settings.travel.trips.header")
        } footer: {
            Text("settings.travel.trips.footer")
        }
        .accessibilityIdentifier("settings.travel.trips")
    }

    private func tripRow(_ trip: TravelTrip) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(trip.start.formatted(date: .abbreviated, time: .shortened))
                Text(trip.end.formatted(date: .abbreviated, time: .omitted))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if trip.autoEnter {
                Spacer()
                Image(systemName: "bolt.fill")
                    .foregroundStyle(Theme.accent)
                    .accessibilityHidden(true)
            }
        }
    }

    /// "Tu voyages ?": off by default, one line of explanation.
    private var detectionSection: some View {
        @Bindable var travel = model.travel
        return Section {
            Toggle("settings.travel.suggest", isOn: $travel.enabled)
                .accessibilityIdentifier("settings.travel.suggest")
            if travel.enabled || travel.usualCount > 0 {
                Button("settings.travel.forget.button", role: .destructive) { confirmForget = true }
                    .disabled(travel.usualCount == 0)
                    .accessibilityIdentifier("settings.travel.forget")
            }
        } header: {
            Text("settings.travel.detection.header")
        } footer: {
            Text("settings.travel.detection.footer")
        }
    }

    @ViewBuilder private var statusRow: some View {
        if let status, status.active {
            Label {
                VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                    Text(status.exiting ? "Retour en cours" : "Travel Mode activé")
                    if let at = status.enteredAt {
                        Text("settings.sinceOffDevice \(Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .abbreviated, time: .shortened)) \(Self.vaultCount(status.hiddenCount))")
                            .font(.footnote)
                            .foregroundStyle(.tertiary)
                    }
                }
            } icon: {
                Image(systemName: "airplane").foregroundStyle(Theme.accent)
            }
        } else {
            Label("settings.travelModeOff", systemImage: "airplane")
                .foregroundStyle(.secondary)
        }
    }

    static func vaultCount(_ n: UInt32) -> String {
        n == 1 ? String(localized: "settings.n1Vault") : String(localized: "settings.vaults \(n)")
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
                    Text("settings.turnOnTravelMode")
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

    private var travelVaults: [FfiVault] {
        model.session.allVaults.filter { personalVaultIDs?.contains($0.id) ?? true }
    }

    private func reload() async {
        status = try? await model.session.travelStatus()
        if let plan = try? await model.session.travelPlan() { personalVaultIDs = Set(plan.map(\.vaultId)) }
        if status?.active != true { itemPlan = try? await model.session.travelItemPlan() }
    }

    private func enter() async {
        working = true
        defer { working = false }
        errorMessage = nil
        do {
            status = try await model.enterTravel(reason: String(localized: "settings.turnOnTravelMode"))
        } catch is CancellationError {
            // The owner cancelled the confirmation: nothing to explain.
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
            model.showToast(String(localized: "travel.toast.back"))
        } catch {
            errorMessage = VaultError(error).localizedMessage
            await reload()
        }
    }
}
