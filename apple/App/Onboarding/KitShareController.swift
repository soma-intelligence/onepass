import Foundation
import SwiftUI
import VaultKit
#if os(macOS)
import AppKit
import UniformTypeIdentifiers
#else
import UIKit
#endif

#if os(iOS) || os(visionOS)
/// The share sheet for the Emergency Kit file, behind the save warning (spec 4). Photos,
/// pasteboard, contacts, reading list, messaging, mail, social networks and collaboration links
/// are excluded (`EmergencyKitSharing`); "Enregistrer dans Fichiers", AirDrop and printing stay.
struct KitShareController: UIViewControllerRepresentable {
    let url: URL
    let onComplete: () -> Void

    static var excludedActivityTypes: [UIActivity.ActivityType] {
        EmergencyKitSharing.excludedActivityTypes.map(UIActivity.ActivityType.init(rawValue:))
    }

    func makeUIViewController(context: Context) -> UIActivityViewController {
        #if DEBUG
        let symbolic: Set<UIActivity.ActivityType> = [
            .saveToCameraRoll, .copyToPasteboard, .assignToContact, .addToReadingList,
            .message, .mail, .postToFacebook, .postToTwitter, .postToWeibo,
            .postToTencentWeibo, .postToFlickr, .postToVimeo,
            .collaborationCopyLink, .collaborationInviteWithLink,
        ]
        assert(symbolic == Set(Self.excludedActivityTypes), "EmergencyKitSharing raw values drifted")
        #endif
        let controller = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        controller.excludedActivityTypes = Self.excludedActivityTypes
        controller.completionWithItemsHandler = { _, _, _, _ in onComplete() }
        return controller
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
#endif

#if os(macOS)
/// Mac save path for the Emergency Kit: a save panel, then a second confirmation when the chosen
/// destination is in iCloud Drive (spec 4). Writes from memory to the chosen file only.
@MainActor
enum KitSavePanel {
    /// Asks for a destination. Nil when the user cancels. Defaults: the Emergency Kit PDF; the
    /// encrypted backup of a safe exit passes its own name, type and message.
    static func chooseDestination(
        fileName: String = EmergencyKitFile.fileName, contentType: UTType = .pdf,
        message: String = String(localized: "Choisis un emplacement hors ligne, par exemple une clé USB. iCloud Drive et les autres clouds synchronisent la Secret Key hors de ce Mac.")
    ) async -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = fileName
        panel.allowedContentTypes = [contentType]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.message = message
        let response: NSApplication.ModalResponse
        if let window = NSApp.keyWindow ?? NSApp.mainWindow {
            response = await panel.beginSheetModal(for: window)
        } else {
            response = panel.runModal()
        }
        guard response == .OK else { return nil }
        return panel.url
    }
}
#endif
