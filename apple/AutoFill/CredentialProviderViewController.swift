import AuthenticationServices

#if os(iOS)
import UIKit
#else
import AppKit
#endif

/// Skeleton of the OnePass credential provider (spec 5). Every request is cancelled with
/// `ASExtensionError.failed` until the AutoFill flows land; the extension only proves that the
/// target builds, is embedded in `OnePass.app/PlugIns` and registers with the system.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    #if os(macOS)
    /// No nib: an `NSViewController` without one must create its own view.
    override func loadView() {
        view = NSView()
    }
    #endif

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        cancelRequest()
    }

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        cancelRequest()
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        cancelRequest()
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        cancelRequest()
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        cancelRequest()
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        cancelRequest()
    }

    override func prepareInterfaceForExtensionConfiguration() {
        cancelRequest()
    }

    #if os(iOS)
    override func prepareInterfaceForUserChoosingTextToInsert() {
        cancelRequest()
    }
    #endif

    private func cancelRequest() {
        extensionContext.cancelRequest(withError: ASExtensionError(.failed))
    }
}
