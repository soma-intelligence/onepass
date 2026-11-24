import GlanceKit

/// Something the app was asked to show from outside (a deep link from a widget or a Control, an
/// App Intent, a verification code link from the system). A route that arrives while the vault is locked waits in `AppModel.pendingRoute`
/// and runs right after the unlock.
enum AppRoute: Equatable {
    case link(OnePassLink)
    case copyTotp(ItemRef)
    /// An `otpauth://` or `otpauth-migration://` link (camera, Safari, another app): the "Ajouter
    /// un code" sheet. Holds the secret: never logged; while waiting for the unlock it lasts 2
    /// minutes and is dropped when the app locks or leaves the screen.
    case otpLink(String)
    /// An `onepass://org/join` invitation, kept as the raw link and read by the core only once the
    /// vault is open (a bad link then shows `org.join.badLink`). Holds the invitation's credential
    /// and member token: waits like `otpLink` (2 minutes, dropped on lock or when the app leaves
    /// the screen).
    case orgJoin(String)
    /// A settings page, and the part of it to open (`AppModel.settingsFocusRequest`): the Mac's
    /// `onepass://settings/fill-anywhere` from OnePass Fill (`FillAnywhereLink`).
    case settings(SettingsPage, focus: String?)

    /// The route holds a secret: it never waits long, nor past a lock.
    var holdsSecret: Bool {
        switch self {
        case .otpLink, .orgJoin: true
        case .link, .copyTotp, .settings: false
        }
    }
}
