import GlanceKit

/// Something the app was asked to show from outside (a deep link from a widget or a Control, an
/// App Intent). A route that arrives while the vault is locked waits in `AppModel.pendingRoute`
/// and runs right after the unlock.
enum AppRoute: Equatable {
    case link(OnePassLink)
    case copyTotp(ItemRef)
}
