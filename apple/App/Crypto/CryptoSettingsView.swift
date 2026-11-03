import DesignKit
import SwiftUI
import VaultKit

/// Réglages > Crypto: the switch (off by default, per account), what leaves the device, the
/// currency, the balance providers per chain (a public service or the user's own endpoint), the
/// price source, the user's own wallet app for "Ouvrir dans…", and erasing the cached balances.
struct CryptoSettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var confirmErase = false
    /// Presented as a sheet from the Crypto screen (a Done button); a Réglages page otherwise.
    var showsDone = false

    private var watch: CryptoWatch { model.cryptoWatch }

    var body: some View {
        Form {
            Section {
                Toggle(isOn: Binding(get: { watch.isEnabled }, set: { on in watch.update { $0.enabled = on } })) {
                    Text("crypto.settings.enable")
                }
                .accessibilityIdentifier("crypto.settings.enable")
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    Text("crypto.settings.enable.footer")
                    Text("crypto.privacy.notice")
                }
            }
            if watch.isEnabled {
                Section {
                    Picker(selection: Binding(get: { watch.settings.currency }, set: { c in watch.update { $0.currency = c } })) {
                        ForEach(CryptoWatchSettings.currencies, id: \.self) { c in
                            Text(verbatim: c.uppercased()).tag(c)
                        }
                    } label: {
                        Text("crypto.settings.currency")
                    }
                    PriceSourceRow()
                } header: {
                    Text("crypto.settings.prices")
                } footer: {
                    Text("crypto.settings.prices.footer")
                }
                Section {
                    ForEach(CryptoChain.allCases, id: \.self) { chain in
                        EndpointRow(chain: chain)
                    }
                } header: {
                    Text("crypto.settings.providers")
                } footer: {
                    Text("crypto.settings.providers.footer")
                }
                Section {
                    HandoffRow()
                } header: {
                    Text("crypto.action.openIn")
                } footer: {
                    Text("crypto.settings.handoff.footer")
                }
                Section {
                    Button("crypto.settings.erase", role: .destructive) { confirmErase = true }
                } footer: {
                    Text("crypto.settings.erase.footer")
                }
            }
        }
        .settingsPage("crypto.title")
        .toolbar {
            if showsDone {
                ToolbarItem(placement: .confirmationAction) {
                    Button("common.done") { dismiss() }
                }
            }
        }
        .confirmationDialog("crypto.settings.erase.confirm", isPresented: $confirmErase, titleVisibility: .visible) {
            Button("crypto.settings.erase", role: .destructive) {
                watch.update { $0.enabled = false }
            }
            Button("common.cancel", role: .cancel) {}
        }
        .task { await model.prepareCryptoWatch() }
    }
}

/// A chain's balance provider: the presets, or "Mon serveur…" with a URL.
private struct EndpointRow: View {
    @Environment(AppModel.self) private var model
    let chain: CryptoChain
    @State private var editing = false
    @State private var text = ""

    private var watch: CryptoWatch { model.cryptoWatch }

    var body: some View {
        let current = watch.settings.endpoint(for: chain)
        Picker(selection: Binding(
            get: { Self.tag(current) },
            set: { tag in
                if tag == "custom" {
                    text = { if case .custom(let u) = current { return u.absoluteString } else { return "" } }()
                    editing = true
                } else {
                    watch.update { $0.setEndpoint(.preset(tag), for: chain) }
                }
            }
        )) {
            ForEach(CryptoPresets.presets(for: chain)) { p in
                Text(verbatim: p.name).tag(p.id)
            }
            Text(Self.customLabel(current)).tag("custom")
        } label: {
            Text(verbatim: chain.name)
        }
        .alert("crypto.settings.custom.title \(chain.name)", isPresented: $editing) {
            TextField("crypto.settings.custom.placeholder", text: $text)
                #if os(iOS)
                .keyboardType(.URL)
                .textInputAutocapitalization(.never)
                #endif
                .autocorrectionDisabled()
            Button("common.save") {
                if let url = URL(string: text.trimmingCharacters(in: .whitespaces)), CryptoWatchSettings.acceptsCustom(url) {
                    watch.update { $0.setEndpoint(.custom(url), for: chain) }
                } else {
                    model.showToast(String(localized: "crypto.settings.custom.invalid"))
                }
            }
            Button("common.cancel", role: .cancel) {}
        } message: {
            Text(chain == .bitcoin ? "crypto.settings.custom.esplora" : "crypto.settings.custom.rpc")
        }
    }

    static func tag(_ e: CryptoEndpoint) -> String {
        switch e {
        case .preset(let id): id
        case .custom: "custom"
        }
    }

    static func customLabel(_ e: CryptoEndpoint) -> LocalizedStringKey {
        if case .custom(let url) = e { return "crypto.settings.custom.current \(url.host() ?? "")" }
        return "crypto.settings.custom"
    }
}

/// CoinGecko, none (amounts only), or a compatible server of the user's.
private struct PriceSourceRow: View {
    @Environment(AppModel.self) private var model
    @State private var editing = false
    @State private var text = ""

    private var watch: CryptoWatch { model.cryptoWatch }

    var body: some View {
        let current = watch.settings.prices
        Picker(selection: Binding(
            get: { current.map(EndpointRow.tag) ?? "none" },
            set: { tag in
                switch tag {
                case "none": watch.update { $0.prices = nil }
                case "custom":
                    text = { if case .custom(let u) = current { return u.absoluteString } else { return "" } }()
                    editing = true
                default: watch.update { $0.prices = .preset(tag) }
                }
            }
        )) {
            ForEach(CryptoPresets.prices) { p in
                Text(verbatim: p.name).tag(p.id)
            }
            Text(current.map(EndpointRow.customLabel) ?? "crypto.settings.custom").tag("custom")
            Text("crypto.settings.prices.none").tag("none")
        } label: {
            Text("crypto.settings.priceSource")
        }
        .alert("crypto.settings.priceSource", isPresented: $editing) {
            TextField("crypto.settings.custom.placeholder", text: $text)
                #if os(iOS)
                .keyboardType(.URL)
                .textInputAutocapitalization(.never)
                #endif
                .autocorrectionDisabled()
            Button("common.save") {
                if let url = URL(string: text.trimmingCharacters(in: .whitespaces)), CryptoWatchSettings.acceptsCustom(url) {
                    watch.update { $0.prices = .custom(url) }
                } else {
                    model.showToast(String(localized: "crypto.settings.custom.invalid"))
                }
            }
            Button("common.cancel", role: .cancel) {}
        } message: {
            Text("crypto.settings.custom.prices")
        }
    }
}

/// The user's own wallet app: a name and its URL scheme.
private struct HandoffRow: View {
    @Environment(AppModel.self) private var model
    @State private var editing = false
    @State private var name = ""
    @State private var scheme = ""

    private var watch: CryptoWatch { model.cryptoWatch }

    var body: some View {
        Button {
            name = watch.settings.handoffName ?? ""
            scheme = watch.settings.handoffScheme ?? ""
            editing = true
        } label: {
            LabeledContent {
                Text(verbatim: watch.settings.handoffName ?? watch.settings.handoffScheme ?? "")
            } label: {
                Text("crypto.settings.handoff")
            }
        }
        .alert("crypto.settings.handoff", isPresented: $editing) {
            TextField("crypto.settings.handoff.name", text: $name)
            TextField("crypto.settings.handoff.scheme", text: $scheme)
                #if os(iOS)
                .textInputAutocapitalization(.never)
                #endif
                .autocorrectionDisabled()
            Button("common.save") {
                let s = scheme.trimmingCharacters(in: .whitespaces)
                if s.isEmpty {
                    watch.update { $0.handoffScheme = nil; $0.handoffName = nil }
                } else if let normalized = Self.normalized(s) {
                    let n = name.trimmingCharacters(in: .whitespaces)
                    watch.update { $0.handoffScheme = normalized; $0.handoffName = n.isEmpty ? nil : n }
                } else {
                    model.showToast(String(localized: "crypto.settings.handoff.invalid"))
                }
            }
            Button("common.cancel", role: .cancel) {}
        }
    }

    /// `wallet` or `wallet://` becomes `wallet://`; web, file and script schemes are refused.
    static func normalized(_ text: String) -> String? {
        let scheme = text.replacingOccurrences(of: "://", with: "").lowercased()
        guard let first = scheme.first, first.isLetter,
              scheme.allSatisfy({ $0.isLetter || $0.isNumber || "+-.".contains($0) }),
              !["http", "https", "file", "javascript", "data", "mailto", "tel", "sms"].contains(scheme)
        else { return nil }
        return scheme + "://"
    }
}
