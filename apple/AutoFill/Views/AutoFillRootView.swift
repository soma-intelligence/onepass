import DesignKit
import SwiftUI
import VaultKit
#if os(iOS)
import UIKit
#endif

/// The extension's interface: one screen per `AutoFillModel.Screen`. The views only display and
/// forward the user's choices to the model; the model decides and completes the request.
struct AutoFillRootView: View {
    let model: AutoFillModel
    let session: VaultSession
    let request: AutoFillRequest
    /// Site icons, as in the app's lists (the extension keeps its own cache).
    @State private var icons: SiteIconLoader

    init(model: AutoFillModel, session: VaultSession, request: AutoFillRequest) {
        self.model = model
        self.session = session
        self.request = request
        let settings = session.environment.settings
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        _icons = State(initialValue: SiteIconLoader(
            cacheDirectory: caches.appendingPathComponent("OnePass/SiteIcons", isDirectory: true),
            enabled: { settings.siteIconsEnabled }))
    }

    var body: some View {
        screen
            .tint(Theme.accent)
            .environment(\.autofillIcons, icons)
    }

    @ViewBuilder private var screen: some View {
        switch model.screen {
        case .starting, .finished:
            // Before `start` nothing is decided yet; after the end the controller is dismissing the
            // extension and nothing from the vault stays on screen.
            Color.clear
        case .locked:
            UnlockView(model: model, session: session, site: siteName)
        case .noAccount:
            MessageView(
                model: model,
                title: String(localized: "Ouvre OnePass pour configurer ton coffre"),
                systemImage: "lock.shield",
                message: String(localized: "Crée ou restaure ton compte dans l'app OnePass, puis reviens ici."))
        case .needsSecretKey:
            MessageView(
                model: model,
                title: String(localized: "Ouvre OnePass pour configurer ton coffre"),
                systemImage: "key",
                message: String(localized: "Saisis ta Secret Key dans l'app OnePass sur cet appareil, puis reviens ici."))
        case .integrityFailure(let failure):
            IntegrityView(model: model, failure: failure)
        case .list(let matches, let others):
            CandidateListView(
                model: model, session: session, matches: matches, others: others, oneTimeCode: isOneTimeCodeList,
                site: siteName)
        case .passkeyRegistration(let suggestions):
            if case .passkeyRegistration(let registration) = request {
                PasskeyRegistrationView(
                    model: model, session: session, registration: registration, suggestions: suggestions)
            }
        case .save(let existing):
            if case .savePassword(let save) = request {
                SavePasswordView(model: model, session: session, request: save, existing: existing)
            }
        case .textItems(let items):
            TextItemsView(model: model, session: session, items: items)
        case .textFields(let item):
            TextFieldsView(model: model, session: session, item: item)
        case .configuration:
            ConfigurationView(model: model, session: session)
        }
    }

    /// One-time code list, or the list a direct code request falls back to.
    private var isOneTimeCodeList: Bool {
        switch request {
        case .oneTimeCodeList, .credential(_, .oneTimeCode, _, _): true
        default: false
        }
    }

    /// The site or app asking ("exemple.fr"), for the headings: the first service of the request.
    private var siteName: String? {
        let service: String? = switch request {
        case .credentialList(let services, let passkey): passkey?.rpID ?? services.first
        case .oneTimeCodeList(let services): services.first
        case .credential(_, _, let passkey, let service): passkey?.rpID ?? service
        case .passkeyRegistration(let registration): registration.rpID
        case .savePassword(let save): save.service
        case .textToInsert, .configuration: nil
        }
        return service.flatMap(Self.displayHost)
    }

    /// "https://www.exemple.fr/login" gives "exemple.fr"; an app identifier stays as is.
    static func displayHost(_ service: String) -> String? {
        let trimmed = service.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let host = URL(string: trimmed.contains("://") ? trimmed : "https://\(trimmed)")?.host() ?? trimmed
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }
}

extension EnvironmentValues {
    /// The extension's site icon loader (`AutoFillRootView`).
    @Entry var autofillIcons: SiteIconLoader?
}

/// Navigation bar with the title and "Annuler" (every screen), and "Retour" when `back` is set, over
/// the grouped background of the app's iPhone screens.
struct AutoFillScaffold<Content: View>: View {
    let title: Text
    let model: AutoFillModel
    var back: (() -> Void)?
    @ViewBuilder let content: Content

    var body: some View {
        NavigationStack {
            content
                .background(AutoFillBackground())
                .navigationTitle(title)
                #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
                #endif
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Annuler") { model.cancel() }
                            .accessibilityIdentifier("autofill.cancel")
                    }
                    if let back {
                        ToolbarItem(placement: .navigation) {
                            Button("Retour", systemImage: "chevron.backward", action: back)
                                .accessibilityIdentifier("autofill.back")
                        }
                    }
                }
        }
    }
}

// MARK: - Design (the app's iPhone cards)

/// The screen behind the cards: grouped background, a faint accent glow on top (iOS); the
/// window's own material on the Mac.
struct AutoFillBackground: View {
    var body: some View {
        #if os(iOS)
        Color(uiColor: .systemGroupedBackground)
            .overlay(alignment: .top) {
                LinearGradient(
                    colors: [Theme.accent.opacity(0.10), Theme.accent.opacity(0)], startPoint: .top, endPoint: .bottom)
                    .frame(height: 260)
            }
            .ignoresSafeArea()
        #else
        Color.clear
        #endif
    }
}

extension View {
    /// A card of the app: the grouped cell color, a hairline, rounded corners.
    func autofillCard() -> some View {
        let shape = RoundedRectangle(cornerRadius: 16, style: .continuous)
        #if os(iOS)
        let fill = Color(uiColor: .secondarySystemGroupedBackground)
        #else
        let fill = Color.primary.opacity(0.05)
        #endif
        return background(fill, in: shape)
            .clipShape(shape)
            .overlay { shape.strokeBorder(Color.primary.opacity(0.06)) }
    }
}

/// Small lowercase label above a card, in the readable accent (the app's card labels).
struct AutoFillLabel: View {
    let text: Text

    init(_ text: LocalizedStringKey) { self.text = Text(text) }
    init(verbatim text: String) { self.text = Text(verbatim: text) }

    var body: some View {
        text
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Theme.readableAccent)
            .padding(.leading, 6)
            .accessibilityAddTraits(.isHeader)
    }
}

/// A row that highlights while pressed, like a list row.
struct AutoFillRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(configuration.isPressed ? Color.primary.opacity(0.08) : .clear)
            .contentShape(Rectangle())
    }
}

/// An item row: site icon (or the category artwork), title, detail, and a trailing view.
struct AutoFillRow<Trailing: View>: View {
    let type: FfiItemType
    let title: String
    let detail: String
    let url: String?
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: 12) {
            AutoFillIcon(type: type, title: title, url: url, size: 36)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: title)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                if !detail.isEmpty {
                    Text(verbatim: detail)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 4)
            trailing
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .frame(minHeight: 56)
    }
}

/// `ItemIcon` with the site icon loaded through the extension's loader.
struct AutoFillIcon: View {
    @Environment(\.autofillIcons) private var loader
    let type: FfiItemType
    let title: String
    let url: String?
    var size: CGFloat = 36
    @State private var icon: Data?

    var body: some View {
        ItemIcon(type: type, title: title, siteIcon: icon, size: size)
            .task(id: url) {
                guard let url, let loader else {
                    icon = nil
                    return
                }
                let loaded = await loader.icon(for: url)
                withAnimation(.easeOut(duration: 0.15)) { icon = loaded }
            }
    }
}

/// Rows in one card, hairlines between them.
struct AutoFillCardRows<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            Group(subviews: content) { rows in
                ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                    if index > 0 { Divider().padding(.leading, 62) }
                    row
                }
            }
        }
        .autofillCard()
    }
}

/// A full-width prominent action (capsule, glass), as the app's lock screen.
struct AutoFillPrimaryButton<Label: View>: View {
    let action: () -> Void
    @ViewBuilder var label: Label

    var body: some View {
        Button(action: action) {
            label
                .font(.system(size: 17, weight: .semibold))
                .frame(maxWidth: .infinity)
                .frame(height: 36)
        }
        .buttonStyle(.glassProminent)
        .buttonBorderShape(.capsule)
        .controlSize(.large)
    }
}

/// The last error of the session, when it is worth showing (a refused biometric prompt is not).
struct SessionErrorText: View {
    let session: VaultSession

    var body: some View {
        if let error = session.lastError, error != .passwordRequired {
            Label(error.localizedMessage, systemImage: "exclamationmark.triangle.fill")
                .font(.footnote)
                .foregroundStyle(.red)
                .accessibilityIdentifier("autofill.error")
        }
    }
}

/// "Open OnePass" screens: nothing can be filled from the extension, only "Annuler".
private struct MessageView: View {
    let model: AutoFillModel
    let title: String
    let systemImage: String
    let message: String

    var body: some View {
        AutoFillScaffold(title: Text(verbatim: ""), model: model) {
            VStack(spacing: 14) {
                AppGlyph(size: 72)
                Text(title)
                    .font(.title3.weight(.semibold))
                    .multilineTextAlignment(.center)
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(32)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .accessibilityElement(children: .combine)
        }
    }
}

/// The core refused tampered data: nothing is shown from the vault.
private struct IntegrityView: View {
    let model: AutoFillModel
    let failure: VaultError

    var body: some View {
        AutoFillScaffold(title: Text("Données refusées"), model: model) {
            VStack(spacing: 16) {
                if case .integrity(let kind) = failure {
                    IntegrityBanner(kind: kind)
                } else {
                    Text(failure.localizedMessage)
                }
                Text("Ouvre OnePass pour en savoir plus.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(20)
        }
    }
}

/// Item title used in accessibility identifiers (`autofill.candidate.<title>`).
func autofillIdentifier(_ prefix: String, _ title: String) -> String {
    "autofill.\(prefix).\(title)"
}

/// A field of a card: the small accent label above its value (the app's detail rows).
struct AutoFillFieldRow<Value: View>: View {
    let label: Text
    @ViewBuilder var value: Value

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            label
                .font(.subheadline.weight(.medium))
                .foregroundStyle(Theme.readableAccent)
            value
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .accessibilityElement(children: .combine)
    }
}

/// The top of the save and passkey screens: the site's icon, a title, one line below.
struct AutoFillHeader: View {
    let type: FfiItemType
    let iconTitle: String
    let url: String?
    let title: Text
    let subtitle: String?

    var body: some View {
        HStack(spacing: 14) {
            AutoFillIcon(type: type, title: iconTitle, url: url, size: 52)
            VStack(alignment: .leading, spacing: 3) {
                title
                    .font(.title3.weight(.bold))
                    .fixedSize(horizontal: false, vertical: true)
                if let subtitle, !subtitle.isEmpty {
                    Text(verbatim: subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 4)
        .accessibilityElement(children: .combine)
    }
}

/// A selectable row: the content, then a filled accent check when chosen (empty ring otherwise).
struct AutoFillChoiceMark: View {
    let selected: Bool

    var body: some View {
        Image(systemName: selected ? "checkmark.circle.fill" : "circle")
            .font(.system(size: 22))
            .foregroundStyle(selected ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.tertiary))
            .accessibilityHidden(true)
    }
}
