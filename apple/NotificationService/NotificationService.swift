import CloudKit
import UserNotifications

/// The alert of an agent request (agent-ready spec 5.2). CloudKit delivers a generic, mutable alert
/// ("Demande d'un agent"); this extension makes it time sensitive and, when the account has a single
/// Mac, names it ("Demande d'un agent sur <nom du Mac>"). The names come from the App Group, written
/// by the app while the vault was open: the sealed request itself cannot be opened here (no vault,
/// no keys in this sandbox). Nothing else is ever added: no item, vault or command, and no action.
final class NotificationService: UNNotificationServiceExtension {
    /// The `OnePassAppGroup` Info.plist key (`$(ONEPASS_APP_GROUP)`, the group of the entitlements).
    static var appGroup: String {
        let value = (Bundle.main.object(forInfoDictionaryKey: "OnePassAppGroup") as? String)?
            .trimmingCharacters(in: .whitespaces) ?? ""
        return value.isEmpty || value.contains("$(") ? "group.me.somalabs.onepass" : value
    }
    /// `PhoneAgents.macNamesKey` in VaultKit.
    static let macNamesKey = "onepass.remote.macNames"

    override func didReceive(
        _ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        guard Self.isAgentRequest(request.content.userInfo),
            let content = request.content.mutableCopy() as? UNMutableNotificationContent
        else {
            contentHandler(request.content)
            return
        }
        content.interruptionLevel = .timeSensitive
        let names = UserDefaults(suiteName: Self.appGroup)?.stringArray(forKey: Self.macNamesKey) ?? []
        if names.count == 1, let name = names.first, !name.isEmpty {
            content.title = String(localized: "Demande d'un agent sur \(name)")
        } else {
            // Several Macs (or none known yet): which one asks is in the sealed request only.
            content.title = String(localized: "Demande d'un agent")
        }
        content.body = ""
        contentHandler(content)
    }

    /// The push of the `remote-<device>` query subscription (`CloudKitRemoteChannel.subscribe`).
    static func isAgentRequest(_ userInfo: [AnyHashable: Any]) -> Bool {
        guard let notification = CKNotification(fromRemoteNotificationDictionary: userInfo) else { return false }
        return notification.subscriptionID?.hasPrefix("remote-") == true
    }
}
