import DesignKit
import SwiftUI
import VaultKit

/// "Utilisation" in an item's detail, below Watchtower: who used the item's secrets, from where and
/// how often (key-use log, spec 2026-11-14). Closed, one line ("Utilisée il y a 2 h · 14 fois ce
/// mois"); open, one row per entry, newest first, and "Effacer le journal". Hidden when the log is
/// empty. Client names come from the clients themselves: always plain `Text`, never Markdown.
struct KeyUseSection: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// The item's log, newest first (loaded by the detail, like the footer's timeline).
    let uses: [FfiKeyUse]
    /// "Effacer le journal" is offered (not in Supprimés récemment, not in a read-only window).
    let editable: Bool
    /// Reads the log again: called when the section opens (a key-use write keeps `updated_at`, so
    /// the detail's own trigger misses a reveal made on this screen).
    let reload: () async -> Void
    /// Empties the log, then reads it again.
    let clear: () async -> Void

    @State private var expanded = false
    @State private var confirmClear = false

    var body: some View {
        if let header = KeyUseSummary.header(uses, now: .now) {
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                Text("item.keyUses")
                    .textCase(.uppercase)
                    .font(.caption.weight(.bold))
                    .tracking(0.6)
                    .foregroundStyle(.secondary)
                    .padding(.leading, Theme.Space.l)
                    .accessibilityAddTraits(.isHeader)
                EditorCard {
                    toggle(header)
                    if expanded {
                        ForEach(Array(uses.enumerated()), id: \.offset) { _, use in
                            CardDivider()
                            row(use)
                        }
                        if editable {
                            CardDivider()
                            Button("item.keyUses.clear", role: .destructive) { confirmClear = true }
                                .buttonStyle(.borderless)
                                .editorRowPadding()
                                .accessibilityIdentifier("item.keyUses.clear")
                        }
                    }
                }
            }
            .accessibilityIdentifier("item.keyUses")
            .confirmationDialog("item.keyUses.clear.title", isPresented: $confirmClear, titleVisibility: .visible) {
                Button("item.keyUses.clear", role: .destructive) {
                    Task {
                        await clear()
                        expanded = false
                    }
                }
                .accessibilityIdentifier("item.keyUses.clear.confirm")
                Button("Annuler", role: .cancel) {}
            } message: {
                Text("item.keyUses.clear.message")
            }
        }
    }

    private func toggle(_ header: String) -> some View {
        Button {
            withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { expanded.toggle() }
            if expanded { Task { await reload() } }
        } label: {
            HStack(spacing: Theme.Space.m) {
                Image(systemName: "clock")
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.secondary)
                    .frame(width: 20)
                    .accessibilityHidden(true)
                Text(verbatim: header)
                    .font(.subheadline)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(expanded ? 90 : 0))
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .editorRowPadding()
        .accessibilityIdentifier("item.keyUses.toggle")
        .accessibilityValue(expanded ? Text("item.expanded") : Text("item.collapsed"))
    }

    private func row(_ use: FfiKeyUse) -> some View {
        let last = Date(timeIntervalSince1970: TimeInterval(use.lastAt))
        return HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
            Image(systemName: Self.symbol(use.channel))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.secondary)
                .frame(width: 20)
                .accessibilityHidden(true)
            Text(verbatim: KeyUseSummary.row(use))
                .font(.subheadline)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Text(last, format: .relative(presentation: .named))
                .font(.caption)
                .foregroundStyle(.secondary)
                .help(FieldDates.timestamp(use.lastAt))
        }
        .editorRowPadding()
        .accessibilityElement(children: .combine)
    }

    static func symbol(_ channel: FfiKeyUseChannel) -> String {
        switch channel {
        case .app: "app.badge"
        case .autoFill: "rectangle.and.pencil.and.ellipsis"
        case .cli: "terminal"
        case .mcp: "sparkles"
        case .sshAgent: "key.horizontal"
        case .desktopFill: "macwindow"
        }
    }
}
