import DesignKit
import SwiftUI
import VaultKit

/// Possible duplicates (specs 2026-11-03-duplicates and 2026-11-08-duplicates-review): the home
/// banner (iPhone) and the review screen. The review is shared: an iPhone tab pushes it, the Mac, iPad
/// and Vision Pro sidebar opens it as a full page (`DuplicatesReviewView.Layout.page`). The core
/// finds the groups, says what differs and how sure a merge is, merges, and refuses any write to a
/// read-only shared copy; this file only shows and asks.
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

#if os(iOS)

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
#endif

// MARK: - Review screen

/// The review (spec 2026-11-08-duplicates-review), in two parts the core decides:
///
/// - Fusion sûre: groups whose copies only add to one another (a website, a tag, a code, a note one
///   holds). Each says what the merge adds; one button merges the ticked ones, the core checking each
///   again before it writes.
/// - À vérifier: groups with a real conflict (two passwords, two usernames…), one at a time, with
///   the question to answer and a table of the lines that differ, one column per copy.
struct DuplicatesReviewView: View {
    /// Where the review sits: pushed in an iPhone tab, or a full page right of the sidebar.
    enum Layout {
        case phone, page
    }

    @Environment(AppModel.self) private var model
    @State private var loader = DuplicatesLoader()
    /// Sure groups the user unticked: left out of the batch.
    @State private var excluded: Set<String> = []
    /// Answers per group id: subject to the item id of the copy whose value wins ("" keeps both notes).
    @State private var answers: [String: [String: String]] = [:]
    @State private var position = 0
    @State private var trashing: FfiDuplicateGroup?
    @State private var busy: Set<String> = []
    @State private var batchBusy = false
    var layout: Layout = .phone

    private var sure: [FfiDuplicateGroup] { loader.groups.filter { $0.confidence == .sure } }
    private var toReview: [FfiDuplicateGroup] { loader.groups.filter { $0.confidence == .review } }
    private var ticked: [FfiDuplicateGroup] {
        sure.filter { !excluded.contains($0.id) && $0.copies.first?.writable == true }
    }

    var body: some View {
        content
            .navigationTitle("duplicates.title")
            .task(id: model.session.summariesRevision) {
                await loader.load(model.session)
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

    @ViewBuilder private var content: some View {
        #if os(iOS)
        if layout == .phone {
            ScrollView {
                sections
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
            }
            .background(PhoneBackground())
            .navigationBarTitleDisplayMode(.inline)
        } else {
            // The page header carries the title: no large navigation title above it.
            page.navigationBarTitleDisplayMode(.inline)
        }
        #else
        page
        #endif
    }

    /// Mac, iPad and Vision Pro: the page header of Watchtower, then the two parts.
    private var page: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                PageHeader(
                    title: String(localized: "duplicates.title"), symbol: "square.on.square", color: .orange,
                    message: headerMessage)
                sections
            }
            .padding(28)
            .frame(maxWidth: 1000, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }

    private var headerMessage: String {
        guard loader.loaded, !loader.groups.isEmpty else { return String(localized: "duplicates.banner.subtitle") }
        return String(localized: "duplicates.header.counts \(sure.count) \(toReview.count)")
    }

    private var sections: some View {
        VStack(alignment: .leading, spacing: 28) {
            if loader.loaded && loader.groups.isEmpty {
                ContentUnavailableView {
                    Label("duplicates.empty.title", systemImage: "checkmark.circle")
                } description: {
                    Text("duplicates.empty.body")
                }
                .frame(maxWidth: .infinity)
                .padding(.top, 40)
            }
            if !sure.isEmpty { sureSection }
            if !toReview.isEmpty { reviewSection }
        }
        .animation(.snappy, value: loader.groups.map(\.id))
    }

    // MARK: Fusion sûre

    private var sureSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            DuplicatesHeading(
                title: String(localized: "duplicates.sure.title"), symbol: "checkmark.seal.fill", color: .green,
                message: String(localized: "duplicates.sure.body"), layout: layout
            ) {
                if layout == .page { mergeAllButton }
            }
            VStack(spacing: 0) {
                ForEach(Array(sure.enumerated()), id: \.element.id) { index, group in
                    if index > 0 { Divider().padding(.leading, layout == .phone ? 52 : 92) }
                    SureGroupRow(
                        group: group, layout: layout, busy: busy.contains(group.id) || batchBusy,
                        included: Binding(
                            get: { !excluded.contains(group.id) },
                            set: { if $0 { excluded.remove(group.id) } else { excluded.insert(group.id) } }),
                        actions: actions(group))
                }
            }
            .padding(.vertical, 4)
            .modifier(DuplicateCardSurface(layout: layout))
            if layout == .phone { mergeAllButton.frame(maxWidth: .infinity) }
        }
        .accessibilityIdentifier("duplicates.sure")
    }

    private var mergeAllButton: some View {
        Button {
            mergeSure()
        } label: {
            HStack(spacing: 6) {
                if batchBusy { ProgressView().controlSize(.small) }
                Text("duplicates.sure.mergeAll \(ticked.count)")
            }
            .frame(maxWidth: layout == .phone ? .infinity : nil)
        }
        .buttonStyle(.glassProminent)
        .controlSize(layout == .phone ? .large : .regular)
        .disabled(ticked.isEmpty || batchBusy)
        .accessibilityIdentifier("duplicates.sure.mergeAll")
    }

    // MARK: À vérifier

    private var reviewSection: some View {
        let list = toReview
        let index = min(position, list.count - 1)
        let group = list[index]
        return VStack(alignment: .leading, spacing: 12) {
            DuplicatesHeading(
                title: String(localized: "duplicates.review.title"), symbol: "questionmark.circle.fill",
                color: .orange, message: String(localized: "duplicates.review.body"), layout: layout
            ) {
                if layout == .page, list.count > 1 { stepper(index: index, count: list.count) }
            }
            if layout == .phone, list.count > 1 {
                stepper(index: index, count: list.count).frame(maxWidth: .infinity, alignment: .trailing)
            }
            ConflictCard(
                group: group, layout: layout, busy: busy.contains(group.id),
                answer: { answer(group, $0) },
                choose: { row, id in answers[group.id, default: [:]][row.subject] = id },
                merge: { mergeReviewed(group) },
                skip: { position = (index + 1) % list.count },
                actions: actions(group))
            .id(group.id)
            .transition(.opacity)
        }
        .accessibilityIdentifier("duplicates.review")
    }

    private func stepper(index: Int, count: Int) -> some View {
        HStack(spacing: 10) {
            Button {
                position = (index + count - 1) % count
            } label: {
                Image(systemName: "chevron.backward")
            }
            .accessibilityLabel(Text("duplicates.review.previous"))
            Text("duplicates.review.position \(index + 1) \(count)")
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)
            Button {
                position = (index + 1) % count
            } label: {
                Image(systemName: "chevron.forward")
            }
            .accessibilityLabel(Text("duplicates.review.next"))
        }
        .buttonStyle(.glass)
        .controlSize(.small)
    }

    // MARK: Answers and actions

    /// The id of the copy whose value `row` keeps: the user's answer, else the core's default ("" for
    /// two notes kept together).
    private func answer(_ group: FfiDuplicateGroup, _ row: FfiDuplicateRow) -> String {
        if let chosen = answers[group.id]?[row.subject] { return chosen }
        guard let w = row.winner, Int(w) < group.copies.count else { return "" }
        return group.copies[Int(w)].summary.id
    }

    private func choices(_ group: FfiDuplicateGroup) -> [FfiDuplicateChoice] {
        group.rows.filter { !$0.subject.isEmpty }.compactMap { row in
            let id = answer(group, row)
            if id.isEmpty { return row.subject == "notes" ? FfiDuplicateChoice(subject: row.subject, fromItemId: nil) : nil }
            return FfiDuplicateChoice(subject: row.subject, fromItemId: id)
        }
    }

    private func actions(_ group: FfiDuplicateGroup) -> DuplicateGroupActions {
        DuplicateGroupActions(
            canChangeOthers: group.copies.dropFirst().contains(where: \.writable),
            archive: { run(group) { try await model.session.archiveDuplicates(others(group)) } },
            trash: { trashing = group },
            dismiss: { run(group) { try await model.session.dismissDuplicates(group.copies.map(\.key)) } })
    }

    private func mergeReviewed(_ group: FfiDuplicateGroup) {
        guard let primary = group.copies.first else { return }
        let picks = choices(group)
        let titleFrom = picks.first { $0.subject == "title" }?.fromItemId
        let title = group.copies.first { $0.summary.id == titleFrom }?.summary.title ?? primary.summary.title
        run(group) {
            try await model.session.mergeDuplicates(
                primary: primary.key, others: group.copies.dropFirst().map(\.key), answers: picks,
                primaryTitle: title)
        }
    }

    private func mergeSure() {
        let ids = ticked.map(\.id)
        batchBusy = true
        Task {
            defer { batchBusy = false }
            do {
                let done = try await model.session.mergeSureDuplicates(ids)
                model.showToast(String(localized: "duplicates.sure.merged \(done.count)"))
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }

    /// Every writable copy but the suggested primary (the first).
    private func others(_ group: FfiDuplicateGroup) -> [FfiItemKey] {
        group.copies.dropFirst().filter(\.writable).map(\.key)
    }

    private func run(_ group: FfiDuplicateGroup, _ op: @escaping () async throws -> Void) {
        busy.insert(group.id)
        Task {
            defer { busy.remove(group.id) }
            do {
                try await op()
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }
}

extension FfiDuplicateGroup: @retroactive Identifiable {}

/// The rarer actions of a group, in its "…" menu.
struct DuplicateGroupActions {
    let canChangeOthers: Bool
    let archive: () -> Void
    let trash: () -> Void
    let dismiss: () -> Void
}

/// Title of a part of the review: a tinted symbol, a heading, one line of explanation.
private struct DuplicatesHeading<Trailing: View>: View {
    let title: String
    let symbol: String
    let color: Color
    let message: String
    let layout: DuplicatesReviewView.Layout
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 3) {
                Label {
                    Text(title)
                } icon: {
                    Image(systemName: symbol).foregroundStyle(color)
                }
                .font(layout == .phone ? .headline : .title2.weight(.semibold))
                Text(message)
                    .font(layout == .phone ? .footnote : .callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            trailing
        }
        .accessibilityElement(children: .contain)
    }
}

/// The card's surface: the iPhone card, or the page card of the Mac and iPad (Watchtower's).
private struct DuplicateCardSurface: ViewModifier {
    let layout: DuplicatesReviewView.Layout

    func body(content: Content) -> some View {
        #if os(iOS)
        if layout == .phone {
            content.phoneCard()
        } else {
            EditorCard { content }
        }
        #else
        EditorCard { content }
        #endif
    }
}

/// What the group is: the kept copy's icon, title and username, then how many copies and where.
private struct DuplicateGroupHeader: View {
    @Environment(AppModel.self) private var model
    let group: FfiDuplicateGroup
    var iconSize: CGFloat = 40

    private var primary: FfiDuplicateCopy? { group.copies.first }

    var body: some View {
        if let primary {
            HStack(spacing: 12) {
                ItemIcon(
                    type: primary.summary.itemType, title: primary.summary.title,
                    siteIcon: model.iconLoader.cachedIcon(
                        for: primary.summary.primaryUrl, title: primary.summary.title),
                    size: iconSize, brand: primary.summary.cardBrand)
                VStack(alignment: .leading, spacing: 2) {
                    Text(primary.summary.title)
                        .font(.body.weight(.semibold))
                        .lineLimit(1)
                    Text(verbatim: DuplicatesText.describe(group))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .accessibilityElement(children: .combine)
        }
    }
}

/// One sure group: tick to merge it with the others, what it is, what the merge adds.
private struct SureGroupRow: View {
    let group: FfiDuplicateGroup
    let layout: DuplicatesReviewView.Layout
    let busy: Bool
    @Binding var included: Bool
    let actions: DuplicateGroupActions

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            tick
            VStack(alignment: .leading, spacing: 6) {
                DuplicateGroupHeader(group: group, iconSize: layout == .phone ? 34 : 40)
                Label {
                    Text(verbatim: DuplicatesText.additions(group))
                        .foregroundStyle(.secondary)
                } icon: {
                    Image(systemName: "plus.circle.fill").foregroundStyle(.green)
                }
                .font(.callout)
                .lineLimit(layout == .phone ? 3 : 2)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            DuplicateActionsMenu(actions: actions)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .disabled(busy)
        .opacity(included ? 1 : 0.55)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("duplicates.sure.group")
    }

    private var tick: some View {
        Button {
            included.toggle()
        } label: {
            Image(systemName: included ? "checkmark.circle.fill" : "circle")
                .font(.title3)
                .foregroundStyle(included ? Theme.readableAccent : Color.secondary)
                .frame(width: 28, height: 28)
                .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .disabled(group.copies.first?.writable != true)
        .accessibilityLabel(Text("duplicates.sure.include"))
        .accessibilityValue(Text(included ? "duplicates.sure.included" : "duplicates.sure.excluded"))
        .accessibilityIdentifier("duplicates.sure.tick")
    }
}

private struct DuplicateActionsMenu: View {
    let actions: DuplicateGroupActions

    var body: some View {
        Menu {
            Button("duplicates.action.notDuplicates", systemImage: "hand.raised", action: actions.dismiss)
            Button("duplicates.action.archiveOthers", systemImage: "archivebox", action: actions.archive)
                .disabled(!actions.canChangeOthers)
            Button("duplicates.action.trashOthers", systemImage: "trash", role: .destructive, action: actions.trash)
                .disabled(!actions.canChangeOthers)
        } label: {
            Image(systemName: "ellipsis")
                .font(.body.weight(.semibold))
                .frame(width: 30, height: 30)
                .contentShape(.rect)
        }
        .menuIndicator(.hidden)
        .menuStyle(.button)
        .buttonStyle(.plain)
        .foregroundStyle(.secondary)
        .fixedSize()
        .accessibilityLabel(Text("duplicates.action.more"))
        .accessibilityIdentifier("duplicates.more")
    }
}

/// One group with a conflict: what it is, the question, the lines that differ, the answers.
private struct ConflictCard: View {
    let group: FfiDuplicateGroup
    let layout: DuplicatesReviewView.Layout
    let busy: Bool
    let answer: (FfiDuplicateRow) -> String
    let choose: (FfiDuplicateRow, String) -> Void
    let merge: () -> Void
    let skip: () -> Void
    let actions: DuplicateGroupActions

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top) {
                DuplicateGroupHeader(group: group, iconSize: 44)
                Spacer(minLength: 8)
                DuplicateActionsMenu(actions: actions)
            }
            Text(verbatim: DuplicatesText.question(group))
                .font(layout == .phone ? .headline : .title3.weight(.semibold))
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("duplicates.question")
            DuplicateDiffTable(group: group, layout: layout, answer: answer, choose: choose)
            Text("duplicates.review.footer")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            buttons
        }
        .padding(layout == .phone ? 14 : 20)
        .modifier(DuplicateCardSurface(layout: layout))
        .disabled(busy)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("duplicates.group")
    }

    @ViewBuilder private var buttons: some View {
        let merge = Button(action: merge) {
            Text("duplicates.action.mergeChoices").frame(maxWidth: layout == .phone ? .infinity : nil)
        }
        .buttonStyle(.glassProminent)
        .disabled(!actions.canChangeOthers)
        .accessibilityIdentifier("duplicates.merge")
        let keep = Button(action: actions.dismiss) {
            Text("duplicates.action.keepBoth").frame(maxWidth: layout == .phone ? .infinity : nil)
        }
        .buttonStyle(.glass)
        .accessibilityIdentifier("duplicates.dismiss")
        let skip = Button("duplicates.action.skip", action: skip)
            .buttonStyle(.glass)
            .accessibilityIdentifier("duplicates.skip")
        if layout == .phone {
            VStack(spacing: 8) {
                merge
                HStack(spacing: 8) { keep; skip }
            }
            .controlSize(.large)
        } else {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 10) {
                    merge.fixedSize()
                    keep.fixedSize()
                    Spacer(minLength: 0)
                    skip.fixedSize()
                }
                VStack(alignment: .leading, spacing: 8) {
                    merge
                    HStack(spacing: 8) { keep; skip }
                }
            }
            .lineLimit(1)
            .controlSize(.large)
        }
    }
}

// MARK: - Diff table

/// The lines that differ, one column per copy (Mac, iPad), or each line with its copies under it
/// (iPhone). A conflict line lets the user pick; an addition says what joins the kept copy.
private struct DuplicateDiffTable: View {
    let group: FfiDuplicateGroup
    let layout: DuplicatesReviewView.Layout
    let answer: (FfiDuplicateRow) -> String
    let choose: (FfiDuplicateRow, String) -> Void

    /// Conflicts first, then what is kept or added.
    private var rows: [FfiDuplicateRow] {
        group.rows.filter { $0.kind == .conflict } + group.rows.filter { $0.kind != .conflict }
    }

    var body: some View {
        if layout == .phone { stacked } else { grid }
    }

    private var grid: some View {
        Grid(alignment: .topLeading, horizontalSpacing: 14, verticalSpacing: 0) {
            GridRow {
                Color.clear.frame(width: 1, height: 1).gridCellUnsizedAxes([.horizontal, .vertical])
                ForEach(group.copies, id: \.summary.id) { copy in
                    CopyHeading(copy: copy, kept: copy.summary.id == group.copies.first?.summary.id)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(.bottom, 10)
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                Divider().gridCellUnsizedAxes(.horizontal)
                GridRow(alignment: .firstTextBaseline) {
                    RowLabel(row: row)
                        .frame(width: 150, alignment: .leading)
                    ForEach(Array(group.copies.enumerated()), id: \.element.summary.id) { index, copy in
                        cell(row, index, copy)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(.vertical, 10)
                if row.kind == .conflict, row.subject == "notes" {
                    GridRow {
                        Color.clear.frame(width: 1, height: 1)
                        bothNotes(row).gridCellColumns(group.copies.count)
                    }
                    .padding(.bottom, 10)
                }
            }
        }
    }

    private var stacked: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                if index > 0 { Divider().padding(.vertical, 10) }
                VStack(alignment: .leading, spacing: 8) {
                    RowLabel(row: row)
                    ForEach(Array(group.copies.enumerated()), id: \.element.summary.id) { i, copy in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(verbatim: copy.summary.title + " · " + copy.vaultName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                            cell(row, i, copy)
                        }
                    }
                    if row.kind == .conflict, row.subject == "notes" { bothNotes(row) }
                }
            }
        }
    }

    @ViewBuilder
    private func cell(_ row: FfiDuplicateRow, _ index: Int, _ copy: FfiDuplicateCopy) -> some View {
        let value = index < row.values.count ? row.values[index] : nil
        let isWinner = answer(row) == copy.summary.id
        if row.kind == .conflict, !row.subject.isEmpty {
            Button {
                choose(row, copy.summary.id)
            } label: {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: isWinner ? "largecircle.fill.circle" : "circle")
                        .foregroundStyle(isWinner ? Theme.readableAccent : Color.secondary)
                        .accessibilityHidden(true)
                    DuplicateValueView(value: value, concealed: row.concealed, row: row, copy: copy, type: group.copies.first?.summary.itemType)
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .disabled(value == nil)
            .accessibilityAddTraits(isWinner ? .isSelected : [])
            .accessibilityIdentifier("duplicates.choice.\(row.subject).\(index)")
        } else {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                DuplicateValueView(value: value, concealed: row.concealed, row: row, copy: copy, type: group.copies.first?.summary.itemType)
                    .opacity(row.kind == .kept && !isWinner ? 0.5 : 1)
                if let tag = tag(row, index, isWinner: isWinner, hasValue: value != nil) {
                    Text(tag)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.12), in: Capsule())
                }
            }
        }
    }

    /// "gardé" on the value a kept line keeps, "ancien" on an older password, "ajouté" on what a copy
    /// brings to the kept one.
    private func tag(_ row: FfiDuplicateRow, _ index: Int, isWinner: Bool, hasValue: Bool) -> LocalizedStringKey? {
        guard hasValue else { return nil }
        switch row.kind {
        case .kept:
            if isWinner { return "duplicates.row.kept" }
            return row.aspect == .password ? "duplicates.row.older" : nil
        case .added:
            if row.subject.isEmpty { return index > 0 ? "duplicates.row.added" : nil }
            return isWinner && index > 0 ? "duplicates.row.added" : nil
        case .conflict:
            return nil
        }
    }

    private func bothNotes(_ row: FfiDuplicateRow) -> some View {
        let both = answer(row).isEmpty
        return Button {
            choose(row, "")
        } label: {
            HStack(spacing: 8) {
                Image(systemName: both ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(both ? Theme.readableAccent : Color.secondary)
                Text("duplicates.row.bothNotes")
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(both ? .isSelected : [])
        .accessibilityIdentifier("duplicates.choice.notes.both")
    }
}

/// Column title: the copy's title, its vault and last edit.
private struct CopyHeading: View {
    let copy: FfiDuplicateCopy
    let kept: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(copy.summary.title).font(.callout.weight(.semibold)).lineLimit(1)
                if !copy.writable {
                    Image(systemName: "lock.fill").font(.caption2).foregroundStyle(.secondary)
                        .accessibilityLabel(Text("duplicates.copy.readOnly"))
                }
            }
            Text(verbatim: "\(copy.vaultName) · \(DuplicatesText.modified(copy))")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The name of a line, and a dot of color for a conflict.
private struct RowLabel: View {
    let row: FfiDuplicateRow

    var body: some View {
        HStack(spacing: 6) {
            if row.kind == .conflict {
                Circle().fill(.orange).frame(width: 7, height: 7).accessibilityHidden(true)
            }
            Text(verbatim: DuplicatesText.rowLabel(row).capitalizedFirst)
                .font(.callout.weight(row.kind == .conflict ? .semibold : .regular))
                .foregroundStyle(row.kind == .conflict ? Color.primary : Color.secondary)
        }
    }
}

/// One value of a line: text, or bullets for a secret with an eye to show it (never for an item that
/// asks to confirm the user first). Masked again after 30 s, on lock and when the session masks all.
private struct DuplicateValueView: View {
    @Environment(AppModel.self) private var model
    let value: FfiFieldValue?
    let concealed: Bool
    let row: FfiDuplicateRow
    let copy: FfiDuplicateCopy
    let type: FfiItemType?
    @State private var shown = false

    var body: some View {
        if let value {
            let text = DuplicatesText.value(value)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                if concealed && !shown {
                    Text(verbatim: hidden(text))
                        .font(.callout.monospaced())
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                        .fixedSize()
                } else {
                    Text(verbatim: text)
                        .font(concealed ? .callout.monospaced() : .callout)
                        .lineLimit(row.aspect == .notes ? 4 : 3)
                        .textSelection(.enabled)
                }
                if concealed && !copy.reprompt {
                    Button {
                        shown.toggle()
                        if shown { model.session.noteActivity() }
                    } label: {
                        Image(systemName: shown ? "eye.slash" : "eye")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help(Text(shown ? "duplicates.secret.hide" : "duplicates.secret.show"))
                    .accessibilityLabel(Text(shown ? "duplicates.secret.hide" : "duplicates.secret.show"))
                }
            }
            .privacySensitive(concealed)
            .onChange(of: model.session.concealGeneration) { shown = false }
            .task(id: shown) {
                guard shown else { return }
                try? await Task.sleep(for: .seconds(30))
                shown = false
            }
        } else {
            Text(verbatim: "–")
                .font(.callout)
                .foregroundStyle(.tertiary)
                .accessibilityLabel(Text("duplicates.value.none"))
        }
    }

    private func hidden(_ text: String) -> String {
        if type == .creditCard, row.subject == "number", let masked = CardMask.text(forNumber: text) { return masked }
        return "••••••••"
    }
}

private extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}

// MARK: - Texts of the review

extension DuplicatesText {
    /// "camille@exemple.fr · 2 copies · Personnel, Famille".
    static func describe(_ group: FfiDuplicateGroup) -> String {
        var parts: [String] = []
        if let user = group.copies.first?.summary.listSubtitle, !user.isEmpty { parts.append(user) }
        parts.append(String(localized: "duplicates.copies \(group.copies.count)"))
        var vaults: [String] = []
        for c in group.copies where !vaults.contains(c.vaultName) { vaults.append(c.vaultName) }
        parts.append(vaults.joined(separator: ", "))
        return parts.joined(separator: " · ")
    }

    /// The name of a line: the aspect, or the field's own label.
    static func rowLabel(_ row: FfiDuplicateRow) -> String {
        if row.aspect == .fields, !row.label.isEmpty {
            return CoreLabels.fieldLabel(FfiField(
                id: row.subject, label: row.label, kind: .text, value: .empty, required: false,
                repeatable: false, autofill: false))
        }
        return aspect(row.aspect)
    }

    /// The question of a group with conflicts.
    static func question(_ group: FfiDuplicateGroup) -> String {
        let conflicts = group.rows.filter { $0.kind == .conflict }
        guard conflicts.count == 1, let row = conflicts.first else {
            return String(localized: "duplicates.question.many \(conflicts.count)")
        }
        switch row.aspect {
        case .password: return String(localized: "duplicates.question.password")
        case .username: return String(localized: "duplicates.question.username")
        case .totp: return String(localized: "duplicates.question.totp")
        case .notes: return String(localized: "duplicates.question.notes")
        default: return String(localized: "duplicates.question.field \(rowLabel(row))")
        }
    }

    /// What merging a sure group adds to the kept copy: "Ajoute : site mail.google.com, étiquette
    /// Famille". Never a secret.
    static func additions(_ group: FfiDuplicateGroup) -> String {
        var parts: [String] = []
        for row in group.rows where row.kind != .conflict {
            switch (row.aspect, row.kind) {
            case (.websites, _), (.tags, _), (.attachments, _), (.passkeys, _):
                let base = Set(lines(row.values.first ?? nil))
                var extra: [String] = []
                for v in row.values.dropFirst() {
                    for line in lines(v) where !base.contains(line) && !extra.contains(line) { extra.append(line) }
                }
                for e in extra {
                    switch row.aspect {
                    case .websites: parts.append(String(localized: "duplicates.add.website \(e)"))
                    case .tags: parts.append(String(localized: "duplicates.add.tag \(e)"))
                    case .attachments: parts.append(String(localized: "duplicates.add.file \(e)"))
                    default: parts.append(String(localized: "duplicates.add.passkey \(e)"))
                    }
                }
            case (.title, _):
                continue
            case (.password, .kept):
                parts.append(String(localized: row.winner == 0 ? "duplicates.add.olderPassword" : "duplicates.add.newerPassword"))
            default:
                // A field or a note one copy holds: named, its value never shown here.
                if let w = row.winner, w > 0 { parts.append(rowLabel(row)) }
            }
        }
        guard !parts.isEmpty else { return String(localized: "duplicates.add.none") }
        return String(localized: "duplicates.adds \(parts.formatted(.list(type: .and, width: .narrow)))")
    }

    private static func lines(_ v: FfiFieldValue?) -> [String] {
        guard case .text(let t)? = v else { return [] }
        return t.split(separator: "\n").map(String.init)
    }

    /// A value as text, as the detail shows it.
    @MainActor static func value(_ v: FfiFieldValue) -> String {
        switch v {
        case .text(let s), .url(let s), .email(let s), .phone(let s): s
        case .password(let s), .concealed(let s), .otp(let s), .mnemonic(let s): s
        case .menu(let s): CoreLabels.menuOption(s)
        case .date(let d): FieldDates.long(d)
        case .monthYear(let year, let month): FieldDates.monthYear(year: year, month: month)
        case .number(let n): String(n)
        case .money(let minor, let currency): Money.formatted(minorUnits: minor, currency: currency)
        case .address(let a): AddressEditor.lines(a)
        case .location(let l): l.address.flatMap { $0.isEmpty ? nil : $0 } ?? LocationEditor.coordinates(l)
        case .sshKey(let k): k.fingerprintSha256
        case .barcode(let value, _): value
        case .passkey(let p): p.rpId
        case .file(let f): f.name
        case .itemLink, .empty: ""
        }
    }
}
