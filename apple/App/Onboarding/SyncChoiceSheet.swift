import SwiftUI
import VaultKit

/// "Où est rangé mon coffre ?" (cross-platform spec D.2, point 1): the OnePass server (default),
/// iCloud, or the user's own server with a "Tester" button (`GET /v1/config`).
struct SyncChoiceSheet: View {
    @Binding var choice: SyncChoice
    @Environment(\.dismiss) private var dismiss

    private enum Option: Hashable { case hosted, iCloud, selfHost }

    @State private var option: Option = .hosted
    @State private var urlText = ""
    @State private var caPEM = ""
    @State private var testing = false
    @State private var testResult: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    row(.hosted, title: MailboxEndpoints.hostedName, detail: "onboarding.syncChoice.hosted.detail")
                    row(.iCloud, title: "iCloud", detail: "onboarding.syncChoice.iCloud.detail")
                    row(.selfHost, title: String(localized: "onboarding.syncChoice.selfHost.title"), detail: nil)
                }
                if option == .selfHost {
                    Section {
                        TextField("onboarding.syncChoice.selfHost.url", text: $urlText)
                            .textContentType(.URL)
                            .autocorrectionDisabled()
                            #if os(iOS)
                            .textInputAutocapitalization(.never)
                            .keyboardType(.URL)
                            #endif
                            .accessibilityIdentifier("onboarding.syncChoice.url")
                        TextField("onboarding.syncChoice.selfHost.ca", text: $caPEM, axis: .vertical)
                            .font(.system(.footnote, design: .monospaced))
                            .lineLimit(3...6)
                            .autocorrectionDisabled()
                        HStack {
                            Button("onboarding.syncChoice.test") { Task { await test() } }
                                .disabled(url == nil || testing)
                                .accessibilityIdentifier("onboarding.syncChoice.test")
                            if testing { ProgressView().controlSize(.small) }
                            if let testResult { Text(testResult).font(.footnote).foregroundStyle(.secondary) }
                        }
                    } footer: {
                        if !urlText.isEmpty, url == nil { Text("onboarding.syncChoice.invalidURL") }
                    }
                }
            }
            .navigationTitle("onboarding.syncChoice.link")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("common.done") { save() }
                        .disabled(option == .selfHost && url == nil)
                        .accessibilityIdentifier("onboarding.syncChoice.done")
                }
            }
        }
        .onAppear(perform: load)
    }

    private func row(_ value: Option, title: String, detail: LocalizedStringKey?) -> some View {
        Button {
            option = value
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).foregroundStyle(.primary)
                    if let detail { Text(detail).font(.footnote).foregroundStyle(.secondary) }
                }
                Spacer()
                if option == value { Image(systemName: "checkmark").foregroundStyle(.tint) }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(option == value ? .isSelected : [])
    }

    /// The URL typed, when the build accepts it.
    private var url: URL? {
        let text = urlText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: text),
              MailboxEndpoints.validate(url, allowHTTP: MailboxEndpoints.allowsLocalHTTP)
        else { return nil }
        return url
    }

    private var pem: String? {
        let text = caPEM.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }

    private func load() {
        switch choice {
        case .hosted: option = .hosted
        case .iCloud: option = .iCloud
        case .selfHost(let url, let ca):
            option = .selfHost
            urlText = url.absoluteString
            caPEM = ca ?? ""
        }
    }

    private func save() {
        switch option {
        case .hosted: choice = .hosted
        case .iCloud: choice = .iCloud
        case .selfHost:
            guard let url else { return }
            choice = .selfHost(url: url, extraCAPEM: pem)
        }
        dismiss()
    }

    private func test() async {
        guard let url else { return }
        testing = true
        defer { testing = false }
        let endpoint = FfiMailboxEndpoint(baseUrl: url.absoluteString, extraCaPem: pem)
        do {
            _ = try await FfiMailboxProvisioning(databasePath: "").check(endpoint)
            testResult = String(localized: "onboarding.syncChoice.testOK")
        } catch {
            testResult = String(localized: "onboarding.syncChoice.testFailed")
        }
    }
}
