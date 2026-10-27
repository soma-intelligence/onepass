import AuthenticationServices
import Foundation

/// The AutoFill provider state seen by the system, and the system settings the app can open (spec 6).
/// Every call goes to the system; nothing is cached here (the app reads the state again on each
/// return to the foreground).
public enum AutoFillStatus {
    /// OnePass is turned on as an AutoFill provider (`ASCredentialIdentityStore` state).
    public static func isEnabled() async -> Bool {
        await ASCredentialIdentityStore.shared.state().isEnabled
    }

    /// Shows the system prompt that turns the OnePass extension on (iOS 18+, macOS 15+). Returns
    /// whether the provider is on afterwards. The system ignores a new request within 10 seconds of
    /// the previous one and answers with the current state.
    public static func requestActivation() async -> Bool {
        await ASSettingsHelper.requestToTurnOnCredentialProviderExtension()
    }

    /// Opens the system AutoFill provider settings (fallback when the prompt was refused).
    public static func openProviderSettings() async {
        try? await ASSettingsHelper.openCredentialProviderAppSettings()
    }

    /// Opens the system settings of the verification code app.
    public static func openVerificationCodeSettings() async {
        try? await ASSettingsHelper.openVerificationCodeAppSettings()
    }
}
