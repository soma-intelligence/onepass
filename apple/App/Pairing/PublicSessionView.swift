import DesignKit
import SwiftUI
import VaultKit

/// The guest session of a public device (spec 2b 5.4): the lent items, read only, in memory only,
/// under a banner with the time left and "Terminer". When the session ends (expiry, the owner, lost
/// connection, inactivity, here) the items are gone and the end screen says why.
struct PublicSessionView: View {
    let session: PublicSession
    let onClose: () -> Void

    var body: some View {
        Group {
            if session.isActive {
                PublicSessionBrowser(session: session)
            } else {
                PublicSessionEnded(reason: session.endReason, onClose: onClose)
            }
        }
        // Closing the window ends the session too (ruling A7).
        .onDisappear { session.end() }
    }
}

private struct PublicSessionBrowser: View {
    let session: PublicSession
    @State private var selection: String?
    @State private var query = ""
    #if os(macOS)
    @State private var titlebarHeight: CGFloat = 52
    #endif

    private var items: [FfiItem] {
        let sorted = session.items.sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return sorted }
        return sorted.filter { $0.title.localizedStandardContains(q) }
    }

    var body: some View {
        #if os(macOS)
        // On the Mac a top inset of the whole split view reaches neither column (rows and the item's
        // header sat under the banner and the title bar): the banner is an inset of the detail column,
        // as the item list's header is in the main window, and the sidebar clears the title bar itself.
        split
            .onChange(of: selection) { session.noteActivity() }
            .onChange(of: query) { session.noteActivity() }
        #else
        split
            .safeAreaInset(edge: .top, spacing: 0) {
                PublicSessionBanner(session: session)
            }
            .onChange(of: selection) { session.noteActivity() }
            .onChange(of: query) { session.noteActivity() }
        #endif
    }

    private var split: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            Group {
                if let item = session.items.first(where: { $0.id == selection }) {
                    PublicItemDetail(item: item, session: session)
                        .id(item.id)
                } else {
                    ContentUnavailableView(
                        "Choisis un élément", systemImage: "list.bullet.rectangle",
                        description: Text("Lecture seule. Tes copies s'effacent du presse-papiers après 30 s."))
                }
            }
            #if os(macOS)
            .safeAreaInset(edge: .top, spacing: 0) {
                PublicSessionBanner(session: session)
            }
            #endif
        }
    }

    /// The lent items. Mac: the sidebar column reports no top safe area (`Sidebar`), so the list starts
    /// below the title bar, its height read from the window.
    @ViewBuilder private var sidebar: some View {
        #if os(macOS)
        VStack(spacing: 0) {
            Color.clear.frame(height: titlebarHeight)
            itemList.frame(minHeight: 0, maxHeight: .infinity)
        }
        .background { TitlebarHeightReader(height: $titlebarHeight) }
        .navigationSplitViewColumnWidth(min: 240, ideal: 280, max: 340)
        #else
        itemList
        #endif
    }

    private var itemList: some View {
        List(selection: $selection) {
            ForEach(items, id: \.id) { item in
                NavigationLink(value: item.id) {
                    HStack(spacing: 12) {
                        ItemIcon(type: item.itemType, title: item.title, siteIcon: nil, size: 34)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(item.title).lineLimit(1)
                            Text(ItemCategory.of(item.itemType).singular)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .accessibilityIdentifier("guest.item.\(item.id)")
            }
        }
        .overlay {
            if items.isEmpty {
                ContentUnavailableView.search(text: query)
            }
        }
        .searchable(text: $query, prompt: Text("Rechercher"))
        .navigationTitle("Éléments prêtés")
    }
}

/// "Session invitée · se termine dans N min" (seconds in the last minute) and "Terminer".
private struct PublicSessionBanner: View {
    let session: PublicSession

    private var countdown: String {
        let left = Int(session.remaining.rounded(.up))
        if left >= 60 {
            let minutes = Int((Double(left) / 60).rounded(.up))
            return String(localized: "Session invitée · se termine dans \(minutes) min")
        }
        return String(localized: "Session invitée · se termine dans \(left) s")
    }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "person.badge.clock")
                .font(.body.weight(.semibold))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text(countdown)
                .font(.subheadline.weight(.semibold))
                .monospacedDigit()
                .contentTransition(.numericText())
                .lineLimit(2)
                .accessibilityIdentifier("guest.countdown")
            Spacer(minLength: 8)
            Button("Terminer") { session.end() }
                .buttonStyle(.glass)
                .accessibilityIdentifier("guest.end")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(.orange.opacity(0.14))
        .background(.bar)
    }
}

/// One lent item, read only: its fields as rows of cards (copy, reveal), its websites and notes.
private struct PublicItemDetail: View {
    let item: FfiItem
    let session: PublicSession
    @State private var copied = 0
    @State private var showsCopied = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 14) {
                    ItemIcon(type: item.itemType, title: item.title, siteIcon: nil, size: 52)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.title).font(.title2.bold()).lineLimit(2)
                        Text(ItemCategory.of(item.itemType).singular).foregroundStyle(.secondary)
                    }
                }
                ForEach(item.sections, id: \.id) { section in
                    let fields = section.fields.filter(Self.shown)
                    if !fields.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            if !section.label.isEmpty {
                                Text(section.displayLabel)
                                    .font(.footnote.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                    .padding(.leading, 4)
                            }
                            EditorCard {
                                ForEach(Array(fields.enumerated()), id: \.element.id) { index, field in
                                    if index > 0 { CardDivider() }
                                    PublicFieldRow(field: field) { value in copy(value, label: field.displayLabel) }
                                }
                            }
                        }
                    }
                }
                if !item.urls.isEmpty {
                    EditorCard {
                        ForEach(Array(item.urls.enumerated()), id: \.offset) { index, url in
                            if index > 0 { CardDivider() }
                            ValueRow(
                                label: url.label.isEmpty ? String(localized: "site web") : url.label.detailLabelCase,
                                value: url.url, isSecret: false, monospaced: false, copyIdentifier: nil,
                                allowsLarge: false, onCopy: { copy(url.url, label: String(localized: "Site web")) },
                                onReveal: nil
                            ) { EmptyView() }
                        }
                    }
                }
                if !item.notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    EditorCard {
                        ValueRow(
                            label: String(localized: "notes"), value: item.notes, isSecret: false, monospaced: false,
                            copyIdentifier: nil, allowsLarge: false,
                            onCopy: { copy(item.notes, label: String(localized: "Notes")) }, onReveal: nil
                        ) { EmptyView() }
                    }
                }
                Label("Lecture seule : rien n'est enregistré sur cet appareil.", systemImage: "eye")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: 640, alignment: .leading)
            .padding(20)
            .frame(maxWidth: .infinity)
        }
        .groupedScreen()
        .overlay(alignment: .bottom) {
            if showsCopied {
                Text("Copié · effacé dans 30 s")
                    .font(.subheadline.weight(.medium))
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .glassEffect()
                    .padding(.bottom, 20)
                    .transition(.opacity)
            }
        }
        .task(id: copied) {
            guard copied > 0 else { return }
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            withAnimation { showsCopied = false }
        }
        .onAppear { session.viewed(itemID: item.id) }
    }

    /// Item links point to items this device does not have; blank values are skipped.
    private static func shown(_ field: FfiField) -> Bool {
        if case .itemLink = field.value { return false }
        return !field.value.isBlank
    }

    private func copy(_ value: String, label: String) {
        session.copy(value, label: label, itemID: item.id)
        copied += 1
        withAnimation { showsCopied = true }
    }
}

/// A field of a lent item, drawn with the detail view's read-only rows.
private struct PublicFieldRow: View {
    #if os(iOS) || os(visionOS)
    @Environment(\.isSceneCaptured) private var captured
    #else
    private let captured = false
    #endif
    let field: FfiField
    let onCopy: (String) -> Void

    private var label: String { field.displayLabel.detailLabelCase }

    var body: some View {
        switch field.value {
        case .otp(let secret):
            DetailRow(
                label: label, onCopy: {
                    if let code = TotpCodeView.code(secret, at: Date()) { onCopy(code.code) }
                }, showsMenu: false
            ) {
                TotpCodeView(secret: secret, compact: true)
            } accessory: {
                EmptyView()
            } menu: {
                EmptyView()
            }
            .privacySensitive()
        case .password(let value), .concealed(let value), .mnemonic(let value):
            row(value, secret: true, monospaced: true)
        case .text(let v), .email(let v), .phone(let v), .url(let v):
            row(v, secret: false, monospaced: false)
        case .menu(let v):
            row(CoreLabels.menuOption(v), secret: false, monospaced: false)
        case .date(let d):
            row(FieldDates.long(d), secret: false, monospaced: false)
        case .monthYear(let year, let month):
            row(FieldDates.monthYear(year: year, month: month), secret: false, monospaced: true)
        case .number(let n):
            row(String(n), secret: false, monospaced: true)
        case .money(let minor, let currency):
            row(Money.formatted(minorUnits: minor, currency: currency), secret: false, monospaced: false)
        case .address(let a):
            row(AddressEditor.lines(a), secret: false, monospaced: false)
        case .location(let l):
            row(l.address.flatMap { $0.isEmpty ? nil : $0 } ?? LocationEditor.coordinates(l), secret: false, monospaced: false)
        case .barcode(let value, _):
            row(value, secret: false, monospaced: true)
        case .sshKey(let key):
            if !key.privatePem.isEmpty {
                row(key.privatePem, secret: true, monospaced: true)
            } else {
                row(key.publicOpenssh, secret: false, monospaced: true)
            }
        default:
            VStack(alignment: .leading, spacing: 3) {
                EditorLabel(label)
                ReadOnlyFieldView(field: field)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .editorRowPadding()
        }
    }

    private func row(_ value: String, secret: Bool, monospaced: Bool) -> some View {
        ValueRow(
            label: label, value: value, isSecret: secret, monospaced: monospaced,
            copyIdentifier: "guest.copy.\(field.id)", allowsLarge: field.kind == .password,
            captured: captured, onCopy: { onCopy(value) }, onReveal: nil
        ) { EmptyView() }
        .privacySensitive(secret)
    }
}

/// The session is over: why, and that nothing stayed here.
private struct PublicSessionEnded: View {
    let reason: PublicSession.EndReason?
    let onClose: () -> Void

    private var reasonText: String {
        switch reason {
        case .expired: String(localized: "Le temps accordé est écoulé.")
        case .endedByOwner: String(localized: "Ton autre appareil a terminé la session.")
        case .connectionLost: String(localized: "La connexion avec ton autre appareil a été coupée.")
        case .inactivity: String(localized: "Aucune activité depuis 5 minutes.")
        case .endedHere, nil: String(localized: "Tu as terminé la session.")
        }
    }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 52, weight: .light))
                .foregroundStyle(Theme.accent)
                .accessibilityHidden(true)
            Text("Session terminée")
                .font(.title.bold())
                .accessibilityAddTraits(.isHeader)
            Text(reasonText)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .accessibilityIdentifier("guest.endReason")
            Text("Rien n'est resté sur cet appareil et le presse-papiers a été vidé.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                onClose()
            } label: {
                Text("Fermer").font(.headline).frame(minWidth: 160).frame(height: Platform.isMac ? 24 : 40)
            }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .accessibilityIdentifier("guest.close")
        }
        .frame(maxWidth: 420)
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
