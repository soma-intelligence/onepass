import Foundation
import UserNotifications
import VaultKit

/// The trip reminders as local notifications of this device (spec 2026-11-14, section 5): a
/// calendar trigger each, identifiers `travel.trip.<id>.eve` and `.go`. Only when the user already
/// allows notifications; `TravelDetection` asks once, when the first trip is saved.
@MainActor
struct SystemTravelReminderCenter: TravelReminderCenter {
    func schedule(_ reminder: TravelReminder) async {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional
        else { return }
        let content = UNMutableNotificationContent()
        switch reminder.kind {
        case .eve:
            content.title = String(localized: "travel.reminder.eve.title")
            content.body = String(localized: "travel.reminder.eve.body")
        case .go:
            content.title = String(localized: "travel.reminder.go.title")
            content.body = String(localized: "travel.reminder.go.body")
        }
        content.sound = .default
        content.interruptionLevel = .active
        // Wall clock components in the current calendar: the eve stays at 19:00 where the owner is.
        let components = Calendar.current.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: reminder.fire)
        let trigger = UNCalendarNotificationTrigger(dateMatching: components, repeats: false)
        let request = UNNotificationRequest(identifier: reminder.id, content: content, trigger: trigger)
        try? await center.add(request)
    }

    func remove(ids: [String]) {
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: ids)
        center.removeDeliveredNotifications(withIdentifiers: ids)
    }
}
