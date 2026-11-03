#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Possible duplicates (spec 2026-11-03-duplicates): the home banner, the review screen with one
/// card per group, and the merge sheet with its preview. The core finds the groups, plans the merge
/// and refuses any write to a read-only shared copy; this file only shows and asks.
@MainActor
@Observable
final class DuplicatesLoader {
    private(set) var groups: [FfiDuplicateGroup] = []
    private(set) var loaded = false

    func load(_ session: VaultSession) async {
        guard session.state == .unlocked else {
            groups = []
            return
        }
        if let found = try? await session.duplicateGroups() {
            groups = found
            loaded = true
        }
    }
}

enum DuplicatesText {
    /// "Même identifiant sur github.com", from the strongest signal of the group.
    static func reason(_ group: FfiDuplicateGroup) -> String {
        switch group.signals.first {
        case .sameTotp: String(localized: "duplicates.reason.sameTotp")
        case .sameCardNumber: String(localized: "duplicates.reason.sameCard")
        case .sameDocumentNumber: String(localized: "duplicates.reason.sameDocument")
        case .sameLogin:
            if let domain = group.domain, !domain.hasPrefix("app:") {
                String(localized: "duplicates.reason.sameLogin \(domain)")
            } else {
                String(localized: "duplicates.reason.sameTitle")
            }
        case .sameTitleAndUsername, nil: String(localized: "duplicates.reason.sameTitle")
        }
    }

    static func symbol(_ group: FfiDuplicateGroup) -> String {
        switch group.signals.first {
        case .sameTotp: "clock.badge.checkmark"
        case .sameCardNumber: "creditcard"
        case .sameDocumentNumber: "person.text.rectangle"
        default: "square.on.square"
        }
    }

    static func aspect(_ a: FfiDuplicateAspect) -> String {
        switch a {
        case .title: String(localized: "duplicates.aspect.title")
        case .username: String(localized: "duplicates.aspect.username")
        case .password: String(localized: "duplicates.aspect.password")
        case .websites: String(localized: "duplicates.aspect.websites")
        case .totp: String(localized: "duplicates.aspect.totp")
        case .passkeys: String(localized: "duplicates.aspect.passkeys")
        case .notes: String(localized: "duplicates.aspect.notes")
        case .fields: String(localized: "duplicates.aspect.fields")
        case .attachments: String(localized: "duplicates.aspect.attachments")
        case .tags: String(localized: "duplicates.aspect.tags")
        }
    }

    /// "Diffère : mot de passe, sites" or "Identique".
    static func differences(_ copy: FfiDuplicateCopy) -> String {
        guard !copy.differences.isEmpty else { return String(localized: "duplicates.copy.same") }
        let list = copy.differences.map(aspect).formatted(.list(type: .and, width: .narrow))
        return String(localized: "duplicates.copy.differs \(list)")
    }

    static func modified(_ copy: FfiDuplicateCopy) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(copy.summary.updatedAt))
        return String(localized: "duplicates.copy.modified \(date.formatted(.relative(presentation: .named)))")
    }
}

// MARK: - Home banner

/// Accueil, under the search and above the Tous les éléments and Favoris tiles: "N doublons
/// possibles" and a chevron. Hidden at zero, and once closed until a group appears that was not on
/// screen then.
struct DuplicatesBanner: View {
    @AppStorage("onepass.home.duplicatesClosed", store: AppModel.browseDefaults) private var closedStored = ""
    /// Owned and loaded by the home screen (this view is empty when hidden).
    let loader: DuplicatesLoader

    private var rule: DuplicateBannerRule { DuplicateBannerRule(stored: closedStored) }

    var body: some View {
        let count = rule.visibleCount(of: loader.groups.map(\.id))
        Group {
            if count > 0 {
                HStack(spacing: 0) {
                    NavigationLink(value: PhoneRoute.duplicates) {
                        HStack(spacing: 12) {
                            SymbolTile(symbol: "square.on.square", color: .orange, size: 30)
                            VStack(alignment: .leading, spacing: 1) {
                                Text("duplicates.banner.title \(count)")
                                    .font(.headline)
                                    .foregroundStyle(.primary)
                                Text("duplicates.banner.subtitle")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .minimumScaleFactor(0.85)
                            }
                            Spacer(minLength: 4)
                            Image(systemName: "chevron.forward")
                                .font(.footnote.weight(.semibold))
                                .foregroundStyle(.tertiary)
                                .accessibilityHidden(true)
                        }
                        .padding(.leading, 14)
                        .padding(.vertical, 10)
                        .contentShape(.rect)
                    }
                    .buttonStyle(RowHighlightButtonStyle())
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("home.duplicates")
                    Button {
                        var r = rule
                        r.close(loader.groups.map(\.id))
                        withAnimation(.snappy) { closedStored = r.stored }
                    } label: {
                        Image(systemName: "xmark")
                            .font(.caption.weight(.bold))
                            .foregroundStyle(.secondary)
                            .frame(width: 44, height: 44)
                            .contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text("duplicates.banner.close"))
                    .accessibilityIdentifier("home.duplicates.close")
                }
                .phoneCard()
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
    }
}

// MARK: - Review screen

/// One card per group: each copy (icon, title, username, vault, last edit, what differs), then the
/// actions Fusionner, Archiver les autres, Supprimer les autres, Pas des doublons.
struct DuplicatesReviewView: View {
    @Environment(AppModel.self) private var model
    @State private var loader = DuplicatesLoader()
    @State private var merging: FfiDuplicateGroup?
    @State private var trashing: FfiDuplicateGroup?
    @State private var busy: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if loader.loaded, loader.groups.isEmpty {
                    ContentUnavailableView {
                        Label("duplicates.empty.title", systemImage: "checkmark.circle")
                    } description: {
                        Text("duplicates.empty.body")
                    }
                    .padding(.top, 60)
                } else {
                    ForEach(loader.groups, id: \.id) { group in
                        DuplicateGroupCard(
                            group: group, busy: busy == group.id,
                            merge: { merging = group },
                            archive: { run(group) { try await model.session.archiveDuplicates(others(group)) } },
                            trash: { trashing = group },
                            dismiss: { run(group) { try await model.session.dismissDuplicates(group.copies.map(\.key)) } })
                        .transition(.opacity.combined(with: .scale(scale: 0.98)))
                    }
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .animation(.snappy, value: loader.groups.map(\.id))
        }
        .background(PhoneBackground())
        .navigationTitle("duplicates.title")
        .navigationBarTitleDisplayMode(.inline)
        .task(id: model.session.summariesRevision) {
            await loader.load(model.session)
            #if DEBUG
            // Captures: `-OnePassDemoList duplicates-merge` opens the first group's merge preview.
            if UserDefaults.standard.string(forKey: "OnePassDemoList") == "duplicates-merge", merging == nil {
                merging = loader.groups.first
            }
            #endif
        }
        .sheet(item: $merging) { group in
            DuplicateMergeSheet(group: group)
        }
        .confirmationDialog(
            "duplicates.trash.title", isPresented: Binding(
                get: { trashing != nil }, set: { if !$0 { trashing = nil } }),
            titleVisibility: .visible, presenting: trashing
        ) { group in
            Button("duplicates.action.trashOthers", role: .destructive) {
                run(group) { try await model.session.trashDuplicates(others(group)) }
            }
            .accessibilityIdentifier("duplicates.trash.confirm")
            Button("common.cancel", role: .cancel) {}
        } message: { _ in
            Text("duplicates.trash.body")
        }
    }

    /// Every writable copy but the suggested primary (the first).
    private func others(_ group: FfiDuplicateGroup) -> [FfiItemKey] {
        group.copies.dropFirst().filter(\.writable).map(\.key)
    }

    private func run(_ group: FfiDuplicateGroup, _ op: @escaping () async throws -> Void) {
        busy = group.id
        Task {
            defer { busy = nil }
            do {
                try await op()
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }
}

extension FfiDuplicateGroup: @retroactive Identifiable {}

private struct DuplicateGroupCard: View {
    let group: FfiDuplicateGroup
    let busy: Bool
    let merge: () -> Void
    let archive: () -> Void
    let trash: () -> Void
    let dismiss: () -> Void

    private var canChangeOthers: Bool { group.copies.dropFirst().contains(where: \.writable) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: DuplicatesText.symbol(group))
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.orange)
                    .frame(width: 22)
                    .accessibilityHidden(true)
                Text(verbatim: DuplicatesText.reason(group))
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.top, 12)
            .padding(.bottom, 6)
            ForEach(Array(group.copies.enumerated()), id: \.element.summary.id) { index, copy in
                if index > 0 { Divider().padding(.leading, 66) }
                DuplicateCopyRow(copy: copy, suggested: index == 0)
            }
            Divider()
            Grid(horizontalSpacing: 8, verticalSpacing: 8) {
                GridRow {
                    Button(action: merge) {
                        Label("duplicates.action.merge", systemImage: "arrow.triangle.merge")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glassProminent)
                    .disabled(!canChangeOthers)
                    .accessibilityIdentifier("duplicates.merge")
                    Button(action: archive) {
                        Label("duplicates.action.archiveOthers", systemImage: "archivebox")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glass)
                    .disabled(!canChangeOthers)
                    .accessibilityIdentifier("duplicates.archive")
                }
                GridRow {
                    Button(role: .destructive, action: trash) {
                        Label("duplicates.action.trashOthers", systemImage: "trash")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glass)
                    .disabled(!canChangeOthers)
                    .accessibilityIdentifier("duplicates.trash")
                    Button(action: dismiss) {
                        Label("duplicates.action.notDuplicates", systemImage: "hand.raised")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glass)
                    .accessibilityIdentifier("duplicates.dismiss")
                }
            }
            .labelStyle(.titleOnly)
            .font(.footnote.weight(.semibold))
            .lineLimit(1)
            .minimumScaleFactor(0.8)
            .controlSize(.small)
            .disabled(busy)
            .padding(12)
        }
        .phoneCard()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("duplicates.group")
    }
}

private struct DuplicateCopyRow: View {
    @Environment(AppModel.self) private var model
    let copy: FfiDuplicateCopy
    let suggested: Bool

    var body: some View {
        NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: copy.summary.vaultId, itemID: copy.summary.id))) {
            HStack(alignment: .top, spacing: 12) {
                ItemIcon(
                    type: copy.summary.itemType, title: copy.summary.title,
                    siteIcon: copy.summary.primaryUrl.flatMap { model.iconLoader.cachedIcon(for: $0) },
                    size: 40, brand: copy.summary.cardBrand)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(copy.summary.title)
                            .font(.body.weight(.semibold))
                            .lineLimit(1)
                        if suggested {
                            badge(Text("duplicates.copy.suggested"), color: Theme.readableAccent)
                        } else if !copy.writable {
                            badge(Text("duplicates.copy.readOnly"), color: .secondary)
                        }
                    }
                    if !copy.summary.subtitle.isEmpty {
                        Text(verbatim: copy.summary.subtitle)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Text(verbatim: "\(copy.vaultName) · \(DuplicatesText.modified(copy))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    if !suggested {
                        Text(verbatim: DuplicatesText.differences(copy))
                            .font(.caption)
                            .foregroundStyle(copy.differences.isEmpty ? Color.secondary : Color.orange)
                            .lineLimit(2)
                    }
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.forward")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .padding(.top, 12)
                    .accessibilityHidden(true)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .contentShape(.rect)
        }
        .buttonStyle(RowHighlightButtonStyle())
        .accessibilityElement(children: .combine)
    }

    private func badge(_ text: Text, color: Color) -> some View {
        text
            .font(.caption2.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.12), in: Capsule())
    }
}

// MARK: - Merge sheet

/// Fusionner: which copy is kept (writable ones only), then what the result will hold, from the
/// core's preview. Nothing is written before the confirm button.
struct DuplicateMergeSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let group: FfiDuplicateGroup
    @State private var primaryID: String
    @State private var preview: FfiMergePreview?
    @State private var merging = false

    init(group: FfiDuplicateGroup) {
        self.group = group
        _primaryID = State(initialValue: group.copies.first?.summary.id ?? "")
    }

    private var primary: FfiDuplicateCopy? { group.copies.first { $0.summary.id == primaryID } }
    private var others: [FfiItemKey] { group.copies.filter { $0.summary.id != primaryID }.map(\.key) }

    var body: some View {
        NavigationStack {
            List {
                keepSection
                resultSection
            }
            .navigationTitle("duplicates.action.merge")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("common.cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("duplicates.action.merge") { merge() }
                        .disabled(preview == nil || merging)
                        .accessibilityIdentifier("duplicates.merge.confirm")
                }
            }
            .task(id: primaryID) { await loadPreview() }
        }
        .presentationDetents([.large])
    }

    private var keepSection: some View {
        Section("duplicates.merge.keep") {
            ForEach(group.copies, id: \.summary.id) { copy in
                keepRow(copy)
            }
        }
    }

    private func keepRow(_ copy: FfiDuplicateCopy) -> some View {
        Button {
            primaryID = copy.summary.id
        } label: {
            HStack(spacing: 12) {
                ItemIcon(
                    type: copy.summary.itemType, title: copy.summary.title, siteIcon: siteIcon(copy.summary),
                    size: 34, brand: copy.summary.cardBrand)
                VStack(alignment: .leading, spacing: 1) {
                    Text(copy.summary.title).font(.body.weight(.medium)).foregroundStyle(.primary)
                    Text(verbatim: "\(copy.vaultName) · \(DuplicatesText.modified(copy))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                if copy.summary.id == primaryID {
                    Image(systemName: "checkmark")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(Theme.readableAccent)
                } else if !copy.writable {
                    Text("duplicates.copy.readOnly").font(.caption).foregroundStyle(.secondary)
                }
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .disabled(!copy.writable)
        .accessibilityAddTraits(copy.summary.id == primaryID ? .isSelected : [])
        .accessibilityIdentifier("duplicates.merge.keep.\(copy.summary.title)")
    }

    @ViewBuilder
    private var resultSection: some View {
        if let preview {
            Section {
                resultHeader(preview.merged)
                ForEach(hosts(preview.merged), id: \.self) { host in
                    Label { Text(verbatim: host) } icon: { Image(systemName: "globe") }
                        .font(.subheadline)
                }
                stat("duplicates.merge.archived \(Int(preview.archivedCount))", "archivebox", preview.archivedCount)
                stat("duplicates.merge.history \(Int(preview.historyAdded))", "clock.arrow.circlepath", preview.historyAdded)
                stat("duplicates.merge.websitesAdded \(Int(preview.websitesAdded))", "plus.circle", preview.websitesAdded)
                stat("duplicates.merge.extraFields \(Int(preview.extraFields))", "square.stack", preview.extraFields)
                stat("duplicates.merge.files \(Int(preview.copiedAttachments))", "paperclip", preview.copiedAttachments)
                stat("duplicates.merge.readOnly \(Int(preview.readOnlyLeft))", "lock", preview.readOnlyLeft)
            } header: {
                Text("duplicates.merge.result")
            } footer: {
                Text("duplicates.merge.footer")
            }
        } else {
            Section { ProgressView().frame(maxWidth: .infinity) }
        }
    }

    /// The websites of the result, one line per host.
    private func hosts(_ item: FfiItem) -> [String] {
        var seen = Set<String>()
        return item.urls.map { URL(string: $0.url)?.host() ?? $0.url }.filter { seen.insert($0).inserted }
    }

    private func siteIcon(_ summary: FfiItemSummary) -> Data? {
        summary.primaryUrl.flatMap { model.iconLoader.cachedIcon(for: $0) }
    }

    private func resultHeader(_ item: FfiItem) -> some View {
        HStack(spacing: 12) {
            ItemIcon(
                type: item.itemType, title: item.title, siteIcon: primary.flatMap { siteIcon($0.summary) },
                size: 40, brand: primary?.summary.cardBrand)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title).font(.headline)
                if let user = primary?.summary.subtitle, !user.isEmpty {
                    Text(verbatim: user).font(.subheadline).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder
    private func stat(_ text: LocalizedStringKey, _ symbol: String, _ n: UInt32) -> some View {
        if n > 0 {
            Label { Text(text) } icon: { Image(systemName: symbol).foregroundStyle(.secondary) }
                .font(.subheadline)
        }
    }

    private func loadPreview() async {
        guard let primary else { return }
        preview = nil
        do {
            preview = try await model.session.duplicateMergePreview(primary: primary.key, others: others)
        } catch {
            model.showToast(VaultError(error).localizedMessage, kind: .error)
        }
    }

    private func merge() {
        guard let primary else { return }
        merging = true
        Task {
            defer { merging = false }
            do {
                try await model.session.mergeDuplicates(
                    primary: primary.key, others: others, primaryTitle: primary.summary.title)
                dismiss()
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }
}
#endif
