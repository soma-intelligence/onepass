import DesignKit
import SwiftUI
import VaultKit

/// "Utiliser ce compte iCloud" (spec 14, ruling E23): checks the new account's zone first. Another
/// OnePass vault there is refused; our own vault is accepted at once; an empty zone asks before the
/// encrypted vault is uploaded there.
struct UseICloudAccountButton: View {
    @Environment(AppModel.self) private var model
    @State private var working = false
    @State private var confirmUpload = false
    @State private var message: String?

    var body: some View {
        Button {
            Task { await check() }
        } label: {
            HStack(spacing: 8) {
                Text("root.useIcloudAccount")
                if working { ProgressView().controlSize(.small) }
            }
        }
        .disabled(working)
        .accessibilityIdentifier("sync.useAccount")
        .confirmationDialog(
            "Utiliser ce compte iCloud ?", isPresented: $confirmUpload, titleVisibility: .visible
        ) {
            Button("root.uploadMyVault") { Task { await accept() } }
                .accessibilityIdentifier("sync.useAccount.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("root.encryptedVaultWillUploaded")
        }
        .alert(
            "Compte iCloud", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })
        ) {
            Button("OK") { message = nil }
        } message: {
            Text(message ?? "")
        }
    }

    private func check() async {
        working = true
        defer { working = false }
        do {
            switch try await model.checkAccountChange() {
            case .otherVault: message = String(localized: "root.icloudAccountAlreadyHolds")
            case .sameVault: await finish(model.acceptAccountChange(expected: .sameVault))
            case .emptyZone: confirmUpload = true
            }
        } catch {
            message = String(localized: "root.cantReadIcloudAccount")
        }
    }

    private func accept() async {
        working = true
        defer { working = false }
        await finish(model.acceptAccountChange(expected: .emptyZone))
    }

    private func finish(_ outcome: AccountChangeOutcome) async {
        switch outcome {
        case .accepted: break
        case .refusedOtherVault: message = String(localized: "root.icloudAccountAlreadyHolds")
        case .changedDuringCheck: message = String(localized: "root.icloudAccountChangedDuring")
        case .failed(let text): message = text
        }
    }
}

/// The iCloud account changed: what happened, and the way to accept the new account. A card on the
/// main views (iPhone list sections, Mac and iPad sidebar).
struct AccountChangedCard: View {
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("app.icloudAccountChanged", systemImage: "person.crop.circle.badge.exclamationmark")
                .font(compact ? .footnote.weight(.semibold) : .subheadline.weight(.semibold))
                .foregroundStyle(.orange)
            Text("root.syncPausedAndVault")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            UseICloudAccountButton()
                .buttonStyle(.glass)
                .controlSize(compact ? .small : .regular)
        }
        .padding(compact ? 10 : 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .accessibilityIdentifier("sync.accountChanged.banner")
    }
}

#if os(iOS)
/// iPhone: the account-changed card at the top of Accueil and Éléments.
struct AccountChangedSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if case .accountChanged = model.syncStatus {
            Section {
                AccountChangedCard()
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 0, leading: 0, bottom: 0, trailing: 0))
            }
        }
    }
}
#endif

/// Réglages > Sync: the refused remote deletions, newest first (kind in French, short id, date).
struct IgnoredDeletionsView: View {
    @Environment(AppModel.self) private var model
    @State private var entries: [FfiIgnoredDeletion] = []
    @State private var confirmClear = false

    var body: some View {
        Form {
            Section {
                if entries.isEmpty {
                    Text("root.noRefusedDeletions").foregroundStyle(.secondary)
                }
                ForEach(Array(entries.enumerated()), id: \.offset) { _, entry in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(Self.kindLabel(entry.kind))
                        Text("\(Self.shortID(entry.id)) · \(Self.date(entry.at))")
                            .font(.footnote.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
            } footer: {
                Text("root.icloudAskedToDelete")
            }
            if !entries.isEmpty {
                Section {
                    Button("root.clearLog", role: .destructive) { confirmClear = true }
                        .accessibilityIdentifier("settings.ignoredDeletions.clear")
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("root.refusedDeletions")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .task { entries = await model.ignoredDeletions().reversed() }
        .confirmationDialog("root.clearLog2", isPresented: $confirmClear, titleVisibility: .visible) {
            Button("root.clearLog", role: .destructive) {
                Task {
                    await model.clearIgnoredDeletions()
                    entries = []
                }
            }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("root.onlyLogClearedItems")
        }
    }

    static func kindLabel(_ kind: UInt8) -> String {
        switch kind {
        case 1: String(localized: "root.accountSettings")
        case 2: String(localized: "root.accountKeys")
        case 3: String(localized: "root.vaultKey")
        case 4: String(localized: "root.vaultNameAndIcon")
        case 5: String(localized: "Élément")
        case 6: String(localized: "root.signedVaultList")
        default: String(localized: "root.unknownRecord")
        }
    }

    /// The first 8 hex characters: enough to tell entries apart.
    static func shortID(_ id: String) -> String { String(id.prefix(8)) }

    static func date(_ unix: Int64) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "fr_FR")
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(unix)))
    }
}
