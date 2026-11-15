import Foundation
import VaultKit
#if canImport(UIKit)
import UIKit
#endif

/// Where an organisation is run from on this device (spec 8.2 C3), and how its invitation links are
/// told apart from the other `onepass://` links.
enum OrgConsole {
    /// Mac and iPad: the devices that sign org changes (spec 8.2 C3). An iPhone joins, it never
    /// creates an organisation.
    @MainActor static var isConsoleDevice: Bool {
        #if os(macOS)
        true
        #elseif os(iOS)
        UIDevice.current.userInterfaceIdiom == .pad
        #else
        false
        #endif
    }

    /// `onepass://org/join`, before any parsing: the link's secrets are read by the core only, after
    /// the unlock (`orgInviteParse`).
    static func isJoinLink(_ url: URL) -> Bool {
        OrgInviteLink.isJoinLink(url)
    }
}
