import SwiftUI
import VaultKit

/// The sharing notices over the main window (sharing spec 10.1, 11.5, 12.3, 14.2): a recovery
/// asked by an organizer (shown locked too), then, once unlocked, the vault invitations, the
/// changed keys and the received items, each opening its page.
struct SharingBanners: View {
    @Environment(AppModel.self) private var model
    @State private var page: Page?
    /// Side margin: none inside the iPhone home, whose blocks already have theirs.
    var horizontalPadding: CGFloat = 16

    enum Page: String, Identifiable {
        case invites, identity, received
        var id: String { rawValue }
    }

    var body: some View {
        let session = model.session
        let sharing = session.sharing
        let unlocked = session.state == .unlocked
        VStack(spacing: 8) {
            ForEach(session.recoveryAlerts, id: \.enrollmentId) { alert in
                RecoveryAlertBanner(alert: alert)
            }
            if unlocked {
                if !sharing.shareInvites.isEmpty {
                    row("sharing.banner.invites \(sharing.shareInvites.count)", symbol: "person.2.badge.plus", page: .invites)
                }
                if !sharing.identityChanges.isEmpty {
                    row("sharing.banner.identity \(sharing.identityChanges.count)", symbol: "key.horizontal", page: .identity)
                }
                if !sharing.receivedItems.isEmpty {
                    row("sharing.banner.received \(sharing.receivedItems.count)", symbol: "tray.and.arrow.down", page: .received)
                }
            }
        }
        .padding(.horizontal, horizontalPadding)
        .padding(.top, horizontalPadding == 0 || session.recoveryAlerts.isEmpty && !(unlocked && hasNotices(sharing)) ? 0 : 8)
        .sheet(item: $page) { page in
            NavigationStack {
                Group {
                    switch page {
                    case .invites: ShareInvitesView()
                    case .identity: IdentityChangeView()
                    case .received: ReceivedItemsView()
                    }
                }
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) { Button("OK") { self.page = nil } }
                }
            }
            .environment(model)
        }
    }

    private func hasNotices(_ s: SharingSnapshot) -> Bool {
        !s.shareInvites.isEmpty || !s.identityChanges.isEmpty || !s.receivedItems.isEmpty
    }

    private func row(_ title: LocalizedStringKey, symbol: String, page: Page) -> some View {
        Button {
            self.page = page
        } label: {
            HStack {
                Label(title, systemImage: symbol)
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("sharing.banner.\(page.rawValue)")
    }
}
