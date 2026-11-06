import DesignKit
import SwiftUI
import VaultKit

/// "Ajouter une passkey", the last row of a login's card (editor and detail). A passkey cannot be
/// typed in: the site creates it, and OnePass, as the AutoFill provider, saves it into this login.
/// So the row opens the page where the site enrolls a passkey: the `enroll` address the site
/// publishes at /.well-known/passkey-endpoints when it has one, else the site itself. That request
/// goes to the login's own site, and only on a tap.
struct AddPasskeyRow: View {
    @Environment(\.openURL) private var openURL
    let item: FfiItem
    /// In the editor the row reads like its other add rows ("ajouter une passkey").
    var editing = false
    /// No website on the login: what the row does instead (the editor adds a website row).
    let onNoWebsite: () -> Void
    @State private var opening = false

    private var host: String? { PasskeyEnrollment.host(of: item) }

    var body: some View {
        Button {
            guard let host else { return onNoWebsite() }
            opening = true
            Task {
                let url = await PasskeyEnrollment.page(for: host)
                opening = false
                openURL(url)
            }
        } label: {
            // Same "+" row as the editor's other add rows; the site it opens sits at the end.
            HStack(spacing: 8) {
                Label(editing ? "item.addPasskeyRow" : "item.addPasskey", systemImage: "plus")
                    .font(.body.weight(.medium))
                    .foregroundStyle(Theme.accent)
                Spacer(minLength: 8)
                if opening {
                    ProgressView().controlSize(.small)
                } else {
                    HStack(spacing: 3) {
                        Text(host ?? String(localized: "item.addWebsiteFirst"))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if host != nil { Image(systemName: "arrow.up.right") }
                    }
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .editorRowPadding()
        .accessibilityIdentifier("item.addPasskey")
    }
}

enum PasskeyEnrollment {
    /// The host of the login's main website, nil when it has none.
    static func host(of item: FfiItem) -> String? {
        guard let raw = (item.urls.first { $0.primary } ?? item.urls.first)?.url else { return nil }
        let host = URL(string: raw)?.host() ?? URL(string: "https://" + raw)?.host()
        return host?.isEmpty == false ? host : nil
    }

    /// The site's passkey enrollment page (W3C passkey endpoints), or its home page.
    static func page(for host: String) async -> URL {
        let home = URL(string: "https://\(host)") ?? URL(string: "https://example.com")!
        guard let wellKnown = URL(string: "https://\(host)/.well-known/passkey-endpoints") else { return home }
        var request = URLRequest(url: wellKnown, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 4)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }
        guard let (data, response) = try? await session.data(for: request),
            (response as? HTTPURLResponse)?.statusCode == 200,
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let enroll = object["enroll"] as? String,
            let url = URL(string: enroll), url.scheme == "https",
            let enrollHost = url.host(), sameSite(enrollHost, host)
        else { return home }
        return url
    }

    /// The enroll page stays on the login's site (same last two labels): a redirect elsewhere is
    /// not followed.
    static func sameSite(_ a: String, _ b: String) -> Bool {
        func base(_ h: String) -> String { h.lowercased().split(separator: ".").suffix(2).joined(separator: ".") }
        return base(a) == base(b)
    }
}
