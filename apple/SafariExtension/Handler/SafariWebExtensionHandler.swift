import Foundation
import SafariRelay
import SafariServices

/// Receives each `browser.runtime.sendNativeMessage` of the OnePass Safari
/// extension (`extension/src/background/safari.ts`) and relays it to the
/// bridge host: the OnePass app's socket in signed builds, the development
/// host in Debug (`BridgeHost.launcher`). Safari routes only this app's own extension here; the bridge
/// pairing and session (spec 6.4 and 6.5) authenticate both ends on top.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    /// One hub for the life of the extension process: host processes (and the
    /// bridge sessions they hold) survive between requests.
    private static let hub = RelayHub(launcher: BridgeHost.launcher())
    private static let queue = DispatchQueue(
        label: "me.somalabs.onepass.safari.relay", qos: .userInitiated, attributes: .concurrent)

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey]
        let request: Result<RelayRequest, RelayError>
        do {
            request = .success(try RelayRequest.parse(message))
        } catch {
            request = .failure(error)
        }
        let reply = Reply(context: context)
        // A poll blocks until the host speaks: never on the calling thread.
        Self.queue.async {
            let response: RelayResponse
            switch request {
            case .success(let r): response = Self.hub.handle(r)
            case .failure(let e): response = .failure(e)
            }
            reply.send(response)
        }
    }
}

/// The request's context, completed once from the relay queue.
private final class Reply: @unchecked Sendable {
    private let context: NSExtensionContext

    init(context: NSExtensionContext) {
        self.context = context
    }

    func send(_ response: RelayResponse) {
        let item = NSExtensionItem()
        item.userInfo = [SFExtensionMessageKey: response.dictionary]
        context.completeRequest(returningItems: [item], completionHandler: nil)
    }
}
