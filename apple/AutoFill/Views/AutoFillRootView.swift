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
    /// The device's accounts when there are several (account switcher of the lists, MACAPP-06).
    var accounts: AutoFillAccounts?
    /// Picking another account: the controller locks this session and opens that one.
    var switchAccount: (@MainActor (String) -> Void)?
    /// Item icons, as in the app's lists: the app's icon pack, else the site's own icon (the
    /// extension keeps its own site icon cache).
    @State private var icons: ItemIconResolver

    init(
        model: AutoFillModel, session: VaultSession, request: AutoFillRequest, accounts: AutoFillAccounts? = nil,
        switchAccount: (@MainActor (String) -> Void)? = nil
    ) {
        self.model = model
        self.session = session
        self.request = request
        self.accounts = accounts
        self.switchAccount = switchAccount
        let settings = session.environment.settings
        _icons = State(initialValue: ItemIconResolver.live(settings: settings))
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
                title: String(localized: "views.openOnepassToSet"),
                systemImage: "lock.shield",
                message: String(localized: "views.createOrRestoreAccount"))
        case .needsSecretKey:
            MessageView(
                model: model,
                title: String(localized: "views.openOnepassToSet"),
                systemImage: "key",
                message: String(localized: "views.enterSecretKeyIn"))
        case .integrityFailure(let failure):
            IntegrityView(model: model, failure: failure)
        case .list(let matches, let others):
            CandidateListView(
                model: model, session: session, matches: matches, others: others, oneTimeCode: isOneTimeCodeList,
                site: siteName, accounts: accounts, switchAccount: switchAccount)
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

    /// The site or app asking ("exemple.fr", "Instagram"), for the headings: the first service of the
    /// request, an app by its name, never its raw identifier (G12).
    private var siteName: String? {
        guard let service = request.primaryService,
            !service.identifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return nil }
        return service.shownName
    }
}

/// The accounts of the device for the list's switcher, and the one this request is open on.
struct AutoFillAccounts {
    let accounts: [AccountProfile]
    let current: String

    /// "Perso", "Travail": the account's label, else its kind.
    static func name(_ account: AccountProfile) -> String {
        let label = account.label.trimmingCharacters(in: .whitespacesAndNewlines)
        if !label.isEmpty { return label }
        switch account.kind {
        case .personal: return String(localized: "views.accountPersonal")
        case .business: return String(localized: "views.accountWork")
        case .managed: return String(localized: "views.accountOrganization")
        }
    }
}

extension EnvironmentValues {
    /// The extension's site icon loader (`AutoFillRootView`).
    @Entry var autofillIcons: ItemIconResolver?
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
                        Button("common.cancel") { model.cancel() }
                            .accessibilityIdentifier("autofill.cancel")
                    }
                    if let back {
                        ToolbarItem(placement: .navigation) {
                            Button("common.back", systemImage: "chevron.backward", action: back)
                                .accessibilityIdentifier("autofill.back")
                        }
                    }
                }
        }
    }
}

// MARK: - Design (the app's iPhone cards)

/// The screen behind the cards: the plain grouped background, like the app's own (iOS); the
/// window's own material on the Mac.
struct AutoFillBackground: View {
    var body: some View {
        #if os(iOS)
        Color(uiColor: .systemGroupedBackground)
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

/// A row that highlights while pressed, like a list row. iPhone: lit the instant the finger lands,
/// the highlight fading on release (`RowHighlightButtonStyle`, shared with the app).
struct AutoFillRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        #if os(iOS)
        RowHighlightButtonStyle().makeBody(configuration: configuration)
        #else
        configuration.label
            .background(configuration.isPressed ? Color.primary.opacity(0.08) : .clear)
            .contentShape(Rectangle())
        #endif
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
        ItemIcon(type: type, title: title, siteIcon: icon ?? loader?.cachedIcon(for: url, title: title), size: size)
            .task(id: url) {
                guard let url, let loader else {
                    icon = nil
                    return
                }
                let loaded = await loader.icon(for: url, title: title)
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
        AutoFillScaffold(title: Text("views.dataRefused"), model: model) {
            VStack(spacing: 16) {
                if case .integrity(let kind) = failure {
                    IntegrityBanner(kind: kind)
                } else {
                    Text(failure.localizedMessage)
                }
                Text("views.openOnepassToLearn")
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
