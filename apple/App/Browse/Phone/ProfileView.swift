#if os(macOS)
import AppKit
#endif
import DesignKit
import SwiftUI
import VaultKit

/// Accueil > Profil (iPhone, iPad), the Profil page of the sidebar (Mac): the account (photo, name,
/// kind of device), Compte and Sécurité (spec 2026-11-14-profile-account-security), then two cards. Identité shows the main identity
/// (name, address on one line, phone, email); Carte de paiement the main card (holder, number as its
/// first and last four digits, expiry). Each card edits its item, or changes which item is the
/// main one ("Automatique" falls back to the first). Without an identity or a card, the card offers
/// to add one. The fields are read through the item loading path; an item behind a reprompt or the
/// Travel Mode guard shows its title only, its fields stay in its detail.
struct ProfileView: View {
    @Environment(AppModel.self) private var model
    #if os(iOS)
    @Environment(\.pushPhoneRoute) private var push
    @Environment(\.openPhoneTab) private var openPhoneTab
    /// On a tab stack of the iPhone; on the iPad split view (and the unfolded iPhone) the rows
    /// open their page as the Mac does.
    @Environment(\.inPhoneTabs) private var inPhoneTabs
    #elseif os(macOS)
    @Environment(\.openSettings) private var openSettingsWindow
    #endif
    @State private var changingPassword = false
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var identity: FfiItem?
    @State private var card: FfiItem?
    @State private var picking: ProfileKind?

    private var session: VaultSession { model.session }

    var body: some View {
        let mainIdentity = session.mainIdentity
        let mainCard = session.mainCard
        let _ = model.settingsRevision
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.Space.l) {
                header
                accountCard
                securityCard
                identityCard(mainIdentity)
                paymentCard(mainCard)
            }
            .padding(.horizontal, Theme.Space.gutter(regularWidth: sizeClass == .regular))
            .padding(.bottom, Theme.Space.xl)
        }
        #if os(iOS)
        .background(PhoneBackground())
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .navigationTitle("Profil")
        .task(id: LoadKey(identity: mainIdentity?.id, card: mainCard?.id, revision: session.summariesRevision)) {
            identity = await load(mainIdentity)
            card = await load(mainCard)
        }
        .sheet(item: $picking) { kind in
            ProfilePicker(kind: kind)
        }
        .sheet(isPresented: $changingPassword) { ChangePasswordSheet() }
        .task { model.watchtower.refreshIfNeeded(session) }
    }

    private struct LoadKey: Equatable {
        let identity: String?
        let card: String?
        let revision: Int
    }

    /// The item behind a summary, nil when it cannot be read or is behind extra protection.
    private func load(_ summary: FfiItemSummary?) async -> FfiItem? {
        guard let summary, session.state == .unlocked else { return nil }
        guard let item = try? await session.loadItem(vaultID: summary.vaultId, itemID: summary.id) else { return nil }
        if item.reprompt || (item.travelGuard && session.isTravelling) { return nil }
        return item
    }

    // MARK: - Header

    private var header: some View {
        VStack(spacing: Theme.Space.s) {
            AccountBadgeAvatar(
                initials: model.initials, photo: model.profileImage, color: model.accountTint,
                badge: model.accountBadge, size: 72)
                .accessibilityHidden(true)
            let name = model.settings.displayName
            if !name.isEmpty {
                Text(verbatim: name)
                    .font(.title2.weight(.bold))
                    .multilineTextAlignment(.center)
            }
            if let label = model.activeProfile?.label, !label.isEmpty, label != name {
                Text(verbatim: label)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Text(deviceText)
                .font(.caption.weight(.semibold))
                .foregroundStyle(model.accountTint)
                .padding(.horizontal, Theme.Space.s)
                .padding(.vertical, Theme.Space.xxs)
                .background(model.accountTint.opacity(0.15), in: .capsule)
                .accessibilityIdentifier("profile.deviceBadge")
        }
        .frame(maxWidth: .infinity)
        .padding(.top, Theme.Space.l)
    }

    private var deviceText: String {
        model.settings.deviceMode == .shared
            ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel")
    }

    // MARK: - Compte

    private var accountCard: some View {
        let profile = model.activeProfile
        return ProfileCard(
            title: "profile.account.title", symbol: "person.text.rectangle.fill", color: AccountPanelTint.accounts,
            canChange: false, onChange: {}
        ) {
            if let profile {
                ProfileRow(label: "profile.account.kind", value: ProfileFacts.kindLabel(profile.kind))
                if let short = ProfileFacts.shortID(profile.accountID), let full = profile.accountID {
                    ProfileNavRow(label: "profile.account.id", value: short, accessory: "doc.on.doc", id: "profile.account.id") {
                        session.copy(full, concealed: false)
                        model.showToast(String(localized: "profile.account.idCopied"))
                    }
                }
                ProfileRow(label: "profile.account.workDomains", value: profile.workDomains.joined(separator: ", "))
            }
            TimelineView(.periodic(from: .now, by: 60)) { context in
                ProfileNavRow(
                    label: "profile.account.sync", value: ProfileFacts.syncLine(model.syncStatus, now: context.date),
                    id: "profile.account.sync"
                ) {
                    openSettings(.sync)
                }
            }
            Spacer().frame(height: Theme.Space.l)
        }
        .accessibilityIdentifier("profile.account")
    }

    // MARK: - Sécurité

    private var securityCard: some View {
        let report = model.watchtower.report
        let issues = ProfileFacts.topIssues(report, among: ProfileFacts.problemChecks)
        let watchtowerText: String = if report == nil {
            String(localized: "profile.security.analyzing")
        } else if issues.isEmpty {
            String(localized: "profile.security.noIssues")
        } else {
            issues.map { issue in
                let title = WatchtowerCard.all.first { $0.checks.contains(issue.check) }?.title ?? issue.check
                return "\(issue.findings) \(title)"
            }.joined(separator: " \u{00B7} ")
        }
        let biometry = model.settings.deviceMode.biometricsAllowed && session.canUseBiometrics
            ? OnboardingModel.biometryName : nil
        return ProfileCard(
            title: "profile.security.title", symbol: "lock.shield.fill", color: SettingsPage.security.tint,
            canChange: false, onChange: {}
        ) {
            ProfileNavRow(
                label: "profile.security.watchtower", value: watchtowerText, id: "profile.security.watchtower",
                leading: { WatchtowerScoreRing(score: report.map { Int($0.score) }) }
            ) {
                #if os(iOS)
                if inPhoneTabs { openPhoneTab(.watchtower); return }
                #endif
                model.page = .watchtower
            }
            ProfileNavRow(
                label: "profile.security.unlock",
                value: ProfileFacts.unlockLine(biometry: biometry, delay: model.settings.autoLockDelay),
                id: "profile.security.unlock"
            ) {
                openSettings(.security)
            }
            ProfileNavRow(label: "profile.security.device", value: deviceText, id: "profile.security.device") {
                openSettings(.security)
            }
            ProfileNavRow(
                label: "profile.security.password", value: String(localized: "profile.security.change"),
                id: "profile.security.password"
            ) {
                changingPassword = true
            }
            ProfileNavRow(
                label: "profile.security.passkeys",
                value: String(localized: "profile.security.passkeyCount \(session.counts().passkeys)"),
                id: "profile.security.passkeys"
            ) {
                #if os(iOS)
                if inPhoneTabs { push(.list(.passkeys)); return }
                #endif
                model.showItems(.passkeys)
            }
            Spacer().frame(height: Theme.Space.l)
        }
        .accessibilityIdentifier("profile.security")
    }

    /// A Réglages page: the Settings window on the Mac, the settings sheet elsewhere.
    private func openSettings(_ page: SettingsPage) {
        model.settingsPageRequest = page
        #if os(macOS)
        NSApp.activate()
        openSettingsWindow()
        #else
        model.showSettings = true
        #endif
    }

    // MARK: - Identité

    @ViewBuilder private func identityCard(_ summary: FfiItemSummary?) -> some View {
        let color = ItemCategory.of(.identity).color
        ProfileCard(
            title: "profile.identity", symbol: ItemCategory.of(.identity).symbol, color: color,
            canChange: summary != nil, onChange: { picking = .identity }
        ) {
            if let summary {
                let loaded = identity.flatMap { $0.id == summary.id ? $0 : nil }
                if let loaded {
                    ProfileRow(label: "profile.name", value: Self.fullName(loaded) ?? summary.title)
                    ProfileRow(label: "profile.address", value: Self.address(loaded))
                    ProfileRow(label: "profile.phone", value: Self.phone(loaded))
                    ProfileRow(label: "profile.email", value: Self.text(loaded, "email"))
                } else {
                    ProfileRow(label: "profile.name", value: summary.title)
                }
                ProfileAction(title: "profile.editIdentity", symbol: "pencil", color: color, id: "profile.identity.edit") {
                    edit(summary)
                }
            } else {
                ProfileEmpty(text: "profile.noIdentity")
                ProfileAction(title: "profile.addIdentity", symbol: "plus", color: color, id: "profile.identity.add") {
                    model.perform(.newItem(.identity))
                }
            }
        }
        .accessibilityIdentifier("profile.identity")
    }

    // MARK: - Carte de paiement

    @ViewBuilder private func paymentCard(_ summary: FfiItemSummary?) -> some View {
        let color = ItemCategory.of(.creditCard).color
        ProfileCard(
            title: "profile.paymentCard", symbol: ItemCategory.of(.creditCard).symbol, color: color,
            canChange: summary != nil, onChange: { picking = .card }
        ) {
            if let summary {
                let loaded = card.flatMap { $0.id == summary.id ? $0 : nil }
                if let loaded {
                    ProfileRow(label: "profile.cardholder", value: Self.text(loaded, "cardholder"))
                    ProfileRow(label: "profile.cardNumber", value: Self.maskedNumber(loaded) ?? summary.cardMask, monospaced: true)
                    ProfileRow(label: "profile.expiry", value: Self.expiry(loaded), monospaced: true)
                } else {
                    ProfileRow(label: "profile.card", value: summary.title)
                    ProfileRow(label: "profile.cardNumber", value: summary.cardMask, monospaced: true)
                }
                ProfileAction(title: "profile.editCard", symbol: "pencil", color: color, id: "profile.card.edit") {
                    edit(summary)
                }
            } else {
                ProfileEmpty(text: "profile.noCard")
                ProfileAction(title: "profile.addCard", symbol: "plus", color: color, id: "profile.card.add") {
                    model.perform(.newItem(.creditCard))
                }
            }
        }
        .accessibilityIdentifier("profile.card")
    }

    /// The item's detail, opening straight in its editor (after its reprompt, if any): pushed on
    /// the iPhone tabs, revealed in the item list elsewhere (iPad, Mac).
    private func edit(_ summary: FfiItemSummary) {
        let ref = ItemRef(vaultID: summary.vaultId, itemID: summary.id)
        model.editOnOpen = ref
        #if os(iOS)
        if inPhoneTabs { push(.item(ref)); return }
        #endif
        model.perform(.reveal(ref))
    }

    // MARK: - Field reading (template ids of the core: identity and credit_card)

    private static func value(_ item: FfiItem, _ id: String) -> FfiFieldValue? {
        item.sections.lazy.flatMap(\.fields).first { $0.id == id }?.value
    }

    private static func text(_ item: FfiItem, _ id: String) -> String? {
        switch value(item, id) {
        case .text(let v), .email(let v), .phone(let v): v.isEmpty ? nil : v
        default: nil
        }
    }

    /// "Camille Anne Durand": first, middle and last names.
    private static func fullName(_ item: FfiItem) -> String? {
        let parts = ["first_name", "middle_name", "last_name"].compactMap { text(item, $0) }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }

    /// The address on one line ("12 rue X, 75011 Paris, France").
    private static func address(_ item: FfiItem) -> String? {
        guard case .address(let a) = value(item, "address") else { return nil }
        let line = AddressEditor.lines(a).replacingOccurrences(of: "\n", with: ", ")
        return line.isEmpty ? nil : line
    }

    /// The mobile phone, else home, else work.
    private static func phone(_ item: FfiItem) -> String? {
        ["mobile_phone", "home_phone", "work_phone"].lazy.compactMap { text(item, $0) }.first
    }

    /// "4242 •••• 4242": the first and last four digits, never more of the number.
    private static func maskedNumber(_ item: FfiItem) -> String? {
        guard case .concealed(let number) = value(item, "number") else { return nil }
        let digits = number.filter { $0 != " " && $0 != "-" }
        guard digits.count >= 8, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return "\(digits.prefix(4)) \u{2022}\u{2022}\u{2022}\u{2022} \(digits.suffix(4))"
    }

    private static func expiry(_ item: FfiItem) -> String? {
        guard case .monthYear(let year, let month) = value(item, "expiry") else { return nil }
        return FieldDates.monthYear(year: year, month: month)
    }
}

/// Which main item a picker chooses.
enum ProfileKind: String, Identifiable {
    case identity, card
    var id: String { rawValue }
}

/// A Profil card: the colored bar on top, the tile and title, "Changer", then the rows.
private struct ProfileCard<Content: View>: View {
    let title: LocalizedStringKey
    let symbol: String
    let color: Color
    let canChange: Bool
    let onChange: () -> Void
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Rectangle()
                .fill(color)
                .frame(height: 4)
                .accessibilityHidden(true)
            HStack(spacing: Theme.Space.m) {
                SymbolTile(symbol: symbol, color: color, size: PhoneCard.headerTileSize)
                Text(title)
                    .font(.headline)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 4)
                if canChange {
                    Button("profile.change", action: onChange)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(Theme.readableAccent)
                        .frame(minHeight: 44)
                        .contentShape(.rect)
                        .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, Theme.Space.l)
            .padding(.vertical, Theme.Space.xs)
            .frame(minHeight: 52)
            Divider().padding(.leading, PhoneCard.headerTextInset)
            content
        }
        .phoneCard()
        // A container: the card's identifier never replaces its rows' own.
        .accessibilityElement(children: .contain)
    }
}

/// A label and its value, on one line each; nothing when the value is empty.
private struct ProfileRow: View {
    let label: LocalizedStringKey
    let value: String?
    var monospaced = false

    var body: some View {
        if let value, !value.isEmpty {
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(verbatim: value)
                    .font(monospaced ? .body.monospacedDigit() : .body)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Theme.Space.l)
            .padding(.top, Theme.Space.s)
            .accessibilityElement(children: .combine)
            .privacySensitive()
        }
    }
}

/// A row that opens something: the label and value as `ProfileRow`, an optional leading view (the
/// Watchtower ring), and a chevron (or `accessory`) at the end.
private struct ProfileNavRow<Leading: View>: View {
    let label: LocalizedStringKey
    let value: String
    var accessory = "chevron.right"
    let id: String
    @ViewBuilder var leading: Leading
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: Theme.Space.m) {
                leading
                VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                    Text(label)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(verbatim: value)
                        .font(.body)
                        .foregroundStyle(.primary)
                        .lineLimit(2)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: Theme.Space.s)
                Image(systemName: accessory)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
            .padding(.horizontal, Theme.Space.l)
            .padding(.top, Theme.Space.s)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier(id)
        .privacySensitive()
    }
}

extension ProfileNavRow where Leading == EmptyView {
    init(label: LocalizedStringKey, value: String, accessory: String = "chevron.right", id: String, action: @escaping () -> Void) {
        self.init(label: label, value: value, accessory: accessory, id: id, leading: { EmptyView() }, action: action)
    }
}

/// The Watchtower score on a small ring: green from 80, orange from 50, red under; empty while the
/// report is computed.
private struct WatchtowerScoreRing: View {
    let score: Int?

    var body: some View {
        let value = score ?? 0
        let color: Color = value >= 80 ? .green : value >= 50 ? .orange : .red
        ZStack {
            Circle().stroke(Color.secondary.opacity(0.2), lineWidth: 4)
            Circle()
                .trim(from: 0, to: CGFloat(value) / 100)
                .stroke(color, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                .rotationEffect(.degrees(-90))
            if let score {
                Text(verbatim: "\(score)")
                    .font(.caption2.monospacedDigit().weight(.semibold))
            }
        }
        .frame(width: 32, height: 32)
        .accessibilityHidden(true)
    }
}

private struct ProfileEmpty: View {
    let text: LocalizedStringKey

    var body: some View {
        Text(text)
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Theme.Space.l)
            .padding(.top, Theme.Space.m)
    }
}

/// The card's action at its foot: "Modifier l'identité", "Ajouter une carte".
private struct ProfileAction: View {
    let title: LocalizedStringKey
    let symbol: String
    let color: Color
    let id: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.subheadline.weight(.semibold))
                .frame(maxWidth: .infinity)
                .frame(minHeight: 44)
        }
        .buttonStyle(.bordered)
        .tint(color)
        .padding(Theme.Space.l)
        .accessibilityIdentifier(id)
    }
}

/// "Changer": "Automatique" (the first identity or card) or one of the account's items of that type.
private struct ProfilePicker: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let kind: ProfileKind

    private var session: VaultSession { model.session }

    var body: some View {
        let type: FfiItemType = kind == .identity ? .identity : .creditCard
        let items = session.items(filter: .category(type), query: "", sort: .title).filter { $0.trashedAt == nil && !$0.archived }
        let current = kind == .identity ? session.mainIdentity?.id : session.mainCard?.id
        NavigationStack {
            List {
                Section {
                    Button {
                        choose(nil)
                    } label: {
                        VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                            Text("profile.automatic").foregroundStyle(.primary)
                            Text(kind == .identity ? "profile.automaticIdentityHint" : "profile.automaticCardHint")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityIdentifier("profile.pick.automatic")
                }
                Section {
                    ForEach(items, id: \.id) { summary in
                        Button {
                            choose(summary)
                        } label: {
                            HStack {
                                ItemListRow(summary: summary, vaultName: nil)
                                if summary.id == current {
                                    Image(systemName: "checkmark")
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(Theme.readableAccent)
                                        .accessibilityLabel(Text("profile.selected"))
                                }
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .navigationTitle(kind == .identity ? "profile.chooseIdentity" : "profile.chooseCard")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #else
            .frame(minWidth: 420, minHeight: 480)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Fermer") { dismiss() }
                }
            }
        }
    }

    private func choose(_ summary: FfiItemSummary?) {
        let ref = summary.map { (vaultID: $0.vaultId, itemID: $0.id) }
        let kind = kind
        Task {
            do {
                if kind == .identity {
                    try await session.setMainIdentity(ref)
                } else {
                    try await session.setMainCard(ref)
                }
                dismiss()
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }
}
