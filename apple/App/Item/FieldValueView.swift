import DesignKit
import SwiftUI
import VaultKit

extension String {
    /// Field labels read like the editor's: "Mot de passe" gives "mot de passe". An acronym first
    /// ("PIN", "URL") stays as is.
    var detailLabelCase: String {
        guard let first, first.isUppercase else { return self }
        if let second = dropFirst().first, second.isUppercase { return self }
        return first.lowercased() + dropFirst()
    }
}

/// One non-empty field in the detail view, drawn for its kind as rows of a card. Secrets are masked
/// (30 s re-mask, masked again on lock and when the scene leaves the foreground, kept masked while
/// the screen is captured on iOS and visionOS); copies go through the session clipboard (90 s,
/// local only, concealed).
struct FieldValueView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    #if os(iOS) || os(visionOS)
    @Environment(\.isSceneCaptured) private var captured
    #else
    private let captured = false
    #endif
    let field: FfiField
    /// Type of the item the field belongs to (card number badge), nil when unknown.
    var itemType: FfiItemType?
    /// Tells the detail a value was copied (toast).
    let onCopied: (String) -> Void

    init(field: FfiField, itemType: FfiItemType? = nil, onCopied: @escaping (String) -> Void) {
        self.field = field
        self.itemType = itemType
        self.onCopied = onCopied
    }

    private var session: VaultSession { model.session }
    private var label: String { field.displayLabel.detailLabelCase }

    var body: some View {
        switch field.value {
        case .otp(let secret):
            TotpFieldView(field: field, captured: captured) { code in copy(code, concealed: true) }
                .id(secret)
                .privacySensitive()
        case .password(let value):
            row(value, secret: true, monospaced: true) {
                StrengthBadge(bits: PasswordStrength.estimatedBits(value))
            }
        case .concealed(let value) where itemType == .creditCard && field.id == "number":
            // The network is read from the number's prefix; the badge itself shows no digit.
            row(value, secret: true, monospaced: true) {
                CardNetworkBadge(network: .detect(number: value))
                    .accessibilityLabel(Text(CardNetworkBadge.CardNetwork.detect(number: value).name))
            }
        case .concealed(let value), .mnemonic(let value):
            row(value, secret: true, monospaced: true)
        case .url(let value):
            urlRow(url: value)
        case .text(let v), .email(let v), .phone(let v):
            row(v, secret: false, monospaced: false)
        case .menu(let v):
            // Stored in French (core menu option), shown in the app's language.
            row(CoreLabels.menuOption(v), secret: false, monospaced: false)
        case .date(let d):
            row(FieldDates.long(d), secret: false, monospaced: false)
        case .monthYear(let year, let month):
            row(FieldDates.monthYear(year: year, month: month), secret: false, monospaced: true)
        case .number(let n):
            row(String(n), secret: false, monospaced: true)
        case .money(let minor, let currency):
            row(Money.formatted(minorUnits: minor, currency: currency), secret: false, monospaced: false)
        case .address(let a):
            row(AddressEditor.lines(a), secret: false, monospaced: false)
        case .location(let l):
            LocationRow(field: field, location: l) {
                copy(l.address.flatMap { $0.isEmpty ? nil : $0 } ?? LocationEditor.coordinates(l), concealed: false)
            }
        case .sshKey(let key):
            sshRows(key)
        case .barcode(let value, let format):
            BarcodeRow(field: field, value: value, format: format) { copy(value, concealed: false) }
        case .itemLink(let id):
            itemLinkRow(id)
        case .passkey(let passkey):
            PasskeyRow(field: field, passkey: passkey)
        case .file:
            VStack(alignment: .leading, spacing: 3) {
                EditorLabel(label)
                ReadOnlyFieldView(field: field)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .editorRowPadding()
        case .empty:
            EmptyView()
        }
    }

    private func row(
        _ value: String, secret: Bool, monospaced: Bool, label: String? = nil, copyIdentifier: String? = nil,
        allowsLarge: Bool? = nil
    ) -> some View {
        row(value, secret: secret, monospaced: monospaced, label: label, copyIdentifier: copyIdentifier,
            allowsLarge: allowsLarge) { EmptyView() }
    }

    private func row<Accessory: View>(
        _ value: String, secret: Bool, monospaced: Bool, label: String? = nil, copyIdentifier: String? = nil,
        allowsLarge: Bool? = nil, @ViewBuilder accessory: () -> Accessory
    ) -> some View {
        let session = session
        let onReveal: ((Bool) -> Void)? = secret ? { _ in session.noteActivity() } : nil
        return ValueRow(
            label: label ?? self.label, value: value, isSecret: secret, monospaced: monospaced,
            copyIdentifier: copyIdentifier ?? "field.copy.\(field.id)",
            // "Afficher en grand" for passwords (barcodes have their own row).
            allowsLarge: allowsLarge ?? (field.kind == .password),
            concealToken: session.concealGeneration, captured: captured,
            onCopy: { copy(value, concealed: secret) },
            onReveal: onReveal,
            accessory: accessory)
            .privacySensitive(secret)
    }

    @ViewBuilder private func sshRows(_ key: FfiSshKey) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            if !key.privatePem.isEmpty {
                row(key.privatePem, secret: true, monospaced: true, label: "\(label) (clé privée)", allowsLarge: false)
            }
            if !key.publicOpenssh.isEmpty {
                if !key.privatePem.isEmpty { CardDivider() }
                row(key.publicOpenssh, secret: false, monospaced: true, label: String(localized: "clé publique"),
                    copyIdentifier: "field.copy.\(field.id).public", allowsLarge: false)
            }
            if !key.fingerprintSha256.isEmpty {
                if !key.privatePem.isEmpty || !key.publicOpenssh.isEmpty { CardDivider() }
                row(key.fingerprintSha256, secret: false, monospaced: true, label: String(localized: "empreinte"),
                    copyIdentifier: "field.copy.\(field.id).fingerprint", allowsLarge: false)
            }
        }
    }

    private func copy(_ value: String, concealed: Bool) {
        session.copy(value, concealed: concealed)
        onCopied(String(localized: "Copié · effacé dans 90 s"))
    }

    private func urlRow(url: String) -> some View {
        let target = Self.openable(url)
        return DetailRow(
            label: label, copyIdentifier: "field.copy.\(field.id)", onCopy: { copy(url, concealed: false) },
            showsMenu: target != nil
        ) {
            Text(url).lineLimit(1).truncationMode(.middle).foregroundStyle(Theme.readableAccent)
        } accessory: {
            EmptyView()
        } menu: {
            if let target {
                Button("Ouvrir dans le navigateur", systemImage: "arrow.up.forward.app") { openURL(target) }
            }
        }
    }

    /// Only web links open (a bare host gets https://); anything else is copy only.
    static func openable(_ text: String) -> URL? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let candidate = trimmed.contains("://") ? trimmed : "https://" + trimmed
        guard let url = URL(string: candidate), let scheme = url.scheme?.lowercased(),
            scheme == "https" || scheme == "http", url.host() != nil
        else { return nil }
        return url
    }

    @ViewBuilder private func itemLinkRow(_ id: String) -> some View {
        let linked = session.summaries.first { $0.id == id }
        VStack(alignment: .leading, spacing: 3) {
            EditorLabel(label)
            if let linked {
                Button {
                    model.editing = false
                    model.selectedItem = ItemRef(vaultID: linked.vaultId, itemID: linked.id)
                } label: {
                    Label(linked.title, systemImage: "link").foregroundStyle(Theme.readableAccent)
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("field.link.\(field.id)")
            } else {
                Text("Élément introuvable").foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .editorRowPadding()
    }
}

// MARK: - Rows

/// A read-only row of a detail card: small accent label above the value, an optional accessory on the
/// right (strength, countdown). Clicking the row copies. On the Mac a hover highlights the row and
/// shows "Copier" and the menu of the other actions; elsewhere the menu (with Copier) stays visible.
struct DetailRow<Value: View, Accessory: View, MenuItems: View>: View {
    let label: String
    let copyIdentifier: String?
    let copyLabel: Text
    let onCopy: (() -> Void)?
    let showsMenu: Bool
    let value: Value
    let accessory: Accessory
    let menu: MenuItems
    @State private var hovered = false
    #if os(iOS)
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Copies made from this row; each one plays the haptic and restarts the "copied" hold.
    @State private var copies = 0
    /// The row shows it was copied: accent tint and a check where the actions glyph sits.
    @State private var showsCopied = false
    #endif

    init(
        label: String, copyIdentifier: String? = nil, copyLabel: Text = Text("Copier"),
        onCopy: (() -> Void)?, showsMenu: Bool,
        @ViewBuilder value: () -> Value, @ViewBuilder accessory: () -> Accessory,
        @ViewBuilder menu: () -> MenuItems
    ) {
        self.label = label
        self.copyIdentifier = copyIdentifier
        self.copyLabel = copyLabel
        self.onCopy = onCopy
        self.showsMenu = showsMenu
        self.value = value()
        self.accessory = accessory()
        self.menu = menu()
    }

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                EditorLabel(label)
                value.frame(maxWidth: .infinity, alignment: .leading)
            }
            #if os(macOS)
            // Same slot at the trailing edge: the accessory gives way to Copier and the menu on hover,
            // so nothing reflows and the accessory sits flush right.
            ZStack(alignment: .trailing) {
                accessory.opacity(hovered ? 0 : 1)
                actions
            }
            #else
            accessory
            actions
            #endif
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .frame(minHeight: 56)
        .background {
            #if os(iOS)
            RoundedRectangle(cornerRadius: 10)
                .fill(Theme.accent.opacity(showsCopied ? 0.12 : 0))
                .padding(4)
            #else
            RoundedRectangle(cornerRadius: 10)
                .fill(Theme.accent.opacity(hovered ? 0.18 : 0))
                .padding(4)
            #endif
        }
        .contentShape(.rect)
        #if os(iOS)
        .onTapGesture { copy() }
        .sensoryFeedback(.success, trigger: copies)
        .task(id: copies) {
            guard copies > 0 else { return }
            try? await Task.sleep(for: Motion.copiedHold)
            guard !Task.isCancelled else { return }
            withAnimation(.easeOut(duration: 0.3)) { showsCopied = false }
        }
        #else
        .onTapGesture { onCopy?() }
        #endif
        #if os(macOS)
        .onHover { inside in
            withAnimation(.easeOut(duration: 0.12)) { hovered = inside }
        }
        #endif
        .accessibilityElement(children: .contain)
        #if os(macOS)
        .modifier(CopyAccessibilityAction(onCopy: onCopy, label: copyLabel))
        #endif
    }

    @ViewBuilder private var actions: some View {
        #if os(macOS)
        HStack(spacing: 4) {
            if let onCopy {
                Button(action: onCopy) {
                    Text("Copier").font(.callout.weight(.medium)).foregroundStyle(Theme.readableAccent)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(copyLabel)
                .accessibilityIdentifier(copyIdentifier ?? "")
            }
            if showsMenu {
                Menu {
                    menu
                } label: {
                    Image(systemName: "chevron.down")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .frame(width: 22, height: 22)
                        .contentShape(.rect)
                }
                .menuStyle(.button)
                .buttonStyle(.borderless)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel(Text(verbatim: "Actions pour \(label)"))
            }
        }
        .opacity(hovered ? 1 : 0)
        .allowsHitTesting(hovered)
        .accessibilityHidden(!hovered)
        #elseif os(iOS)
        if onCopy != nil || showsMenu {
            Menu {
                if onCopy != nil {
                    Button(action: copy) { Label { copyLabel } icon: { Image(systemName: "doc.on.doc") } }
                        .accessibilityIdentifier(copyIdentifier ?? "")
                }
                if showsMenu { menu }
            } label: {
                // Right after a copy the glyph turns into a check for a moment, then back.
                Image(systemName: showsCopied ? "checkmark.circle.fill" : "ellipsis.circle")
                    .contentTransition(reduceMotion ? .opacity : .symbolEffect(.replace))
                    .frame(width: 44, height: 44)
                    .contentShape(.rect)
                    .accessibilityLabel(Text(verbatim: "Actions pour \(label)"))
            }
            .menuStyle(.button)
            .buttonStyle(.borderless)
            .fixedSize()
            .padding(.vertical, -10)
            .padding(.trailing, -10)
        }
        #else
        if onCopy != nil || showsMenu {
            Menu {
                if let onCopy {
                    Button(action: onCopy) { Label { copyLabel } icon: { Image(systemName: "doc.on.doc") } }
                        .accessibilityIdentifier(copyIdentifier ?? "")
                }
                if showsMenu { menu }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .accessibilityLabel(Text(verbatim: "Actions pour \(label)"))
            }
            .menuStyle(.button)
            .buttonStyle(.borderless)
            .fixedSize()
        }
        #endif
    }

    #if os(iOS)
    /// Copies, then says so where the finger is: a success haptic, the row tinted and its glyph
    /// turned into a check for a moment (the toast at the bottom carries the text).
    private func copy() {
        guard let onCopy else { return }
        onCopy()
        copies += 1
        withAnimation(.easeOut(duration: 0.12)) { showsCopied = true }
    }
    #endif
}

/// VoiceOver reaches "Copier" even while the hover buttons are hidden.
private struct CopyAccessibilityAction: ViewModifier {
    let onCopy: (() -> Void)?
    let label: Text

    func body(content: Content) -> some View {
        if let onCopy {
            content.accessibilityAction(named: label, onCopy)
        } else {
            content
        }
    }
}

/// A text value in a detail card, masked when secret. Menu: Révéler / Masquer, Afficher en grand.
/// A revealed secret is masked again after 30 s, when the row goes away, and whenever `concealToken`
/// changes (the session bumps it on lock and when the scene leaves the foreground). While `captured`
/// (screen recording, mirroring, AirPlay) a secret is drawn as bullets, and a revealed one is masked again.
struct ValueRow<Accessory: View>: View {
    let label: String
    let value: String
    let isSecret: Bool
    let monospaced: Bool
    let copyIdentifier: String?
    let allowsLarge: Bool
    let concealToken: Int
    let captured: Bool
    let onCopy: () -> Void
    let onReveal: ((Bool) -> Void)?
    let accessory: Accessory

    private let autoHideAfter: TimeInterval = 30
    @State private var revealed = false
    @State private var revealedAt: Date?
    @State private var large = false

    init(
        label: String, value: String, isSecret: Bool, monospaced: Bool, copyIdentifier: String?,
        allowsLarge: Bool, concealToken: Int = 0, captured: Bool = false,
        onCopy: @escaping () -> Void, onReveal: ((Bool) -> Void)?,
        @ViewBuilder accessory: () -> Accessory
    ) {
        self.label = label
        self.value = value
        self.isSecret = isSecret
        self.monospaced = monospaced
        self.copyIdentifier = copyIdentifier
        self.allowsLarge = allowsLarge
        self.concealToken = concealToken
        self.captured = captured
        self.onCopy = onCopy
        self.onReveal = onReveal
        self.accessory = accessory()
    }

    private var hidden: Bool { isSecret && (!revealed || captured) }

    var body: some View {
        DetailRow(
            label: label, copyIdentifier: copyIdentifier, onCopy: onCopy, showsMenu: isSecret || allowsLarge
        ) {
            Text(hidden ? FieldRow.mask : value)
                .font(monospaced ? .body.monospaced() : .body)
                .textSelection(.disabled)
                .accessibilityLabel(Text(label))
                .accessibilityValue(Text(hidden ? "masqué" : value))
        } accessory: {
            accessory
        } menu: {
            if isSecret {
                Button(revealed ? "Masquer" : "Révéler", systemImage: revealed ? "eye.slash" : "eye") {
                    setRevealed(!revealed)
                }
            }
            if allowsLarge {
                Button("Afficher en grand", systemImage: "arrow.up.left.and.arrow.down.right") { showLarge() }
            }
        }
        .task(id: revealedAt) {
            guard let at = revealedAt else { return }
            try? await Task.sleep(for: .seconds(autoHideAfter))
            if !Task.isCancelled, revealed, Date().timeIntervalSince(at) >= autoHideAfter { setRevealed(false) }
        }
        .onDisappear { if revealed { setRevealed(false) } }
        .onChange(of: concealToken) { if revealed { setRevealed(false) } }
        // Captured: masked now, and still masked once the capture ends.
        .onChange(of: captured) { _, now in if now, revealed { setRevealed(false) } }
        .sheet(isPresented: Binding(get: { large && !hidden }, set: { large = $0 })) {
            VStack(spacing: 16) {
                Text(label).font(.headline)
                Text(value)
                    .font(.system(.largeTitle, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .minimumScaleFactor(0.4)
                Button("Fermer") { large = false }.keyboardShortcut(.cancelAction)
            }
            .padding(32)
            .presentationDetents([.medium])
        }
    }

    private func setRevealed(_ on: Bool) {
        guard isSecret else { return }
        revealed = on
        revealedAt = on ? Date() : nil
        if !on { large = false }
        onReveal?(on)
    }

    /// A secret goes through the same reveal path before it is shown large.
    private func showLarge() {
        if isSecret { setRevealed(true) }
        large = true
    }
}

/// A passkey of a Login (spec 6): the site it signs in to, the account name and the creation date.
/// Nothing secret: the private key never leaves the core.
private struct PasskeyRow: View {
    let field: FfiField
    let passkey: FfiPasskey

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                EditorLabel(field.displayLabel.detailLabelCase)
                Text(passkey.rpId.isEmpty ? String(localized: "Site inconnu") : passkey.rpId)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if !passkey.userName.isEmpty {
                    Text(passkey.userName)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Text("Créée le \(FieldDates.day(passkey.createdAt))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            Image(systemName: "person.badge.key.fill")
                .font(.title3)
                .foregroundStyle(Theme.readableAccent)
                .accessibilityHidden(true)
        }
        .editorRowPadding()
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("field.passkey.\(field.id)")
    }
}

/// Location: the place's label and address (copied on click), a small map with its pin, and
/// "Ouvrir dans Plans". A location never placed (blank coordinates) shows its text only.
private struct LocationRow: View {
    let field: FfiField
    let location: FfiLocation
    let onCopy: () -> Void

    private var point: GeoPoint { GeoPoint(latitude: location.lat, longitude: location.lon) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            DetailRow(
                label: field.displayLabel.detailLabelCase, copyIdentifier: "field.copy.\(field.id)", onCopy: onCopy,
                showsMenu: point.isPlaced
            ) {
                VStack(alignment: .leading, spacing: 2) {
                    if !location.label.isEmpty { Text(location.label) }
                    if let address = location.address, !address.isEmpty {
                        Text(address)
                            .foregroundStyle(location.label.isEmpty ? .primary : .secondary)
                            .font(location.label.isEmpty ? .body : .callout)
                    }
                    // A placed location shows its map below, never raw coordinates.
                    if location.label.isEmpty, location.address?.isEmpty ?? true {
                        Text(point.isPlaced ? String(localized: "Lieu sur la carte") : LocationEditor.coordinates(location))
                            .foregroundStyle(point.isPlaced ? .secondary : .primary)
                    }
                }
            } accessory: {
                EmptyView()
            } menu: {
                Button("Ouvrir dans Plans", systemImage: "map") { location.openInMaps() }
            }
            if point.isPlaced {
                LocationMap(point: point, title: location.label)
                    .frame(height: 140)
                    .padding(.horizontal, 16)
                    .accessibilityIdentifier("field.location.map.\(field.id)")
                Button {
                    location.openInMaps()
                } label: {
                    Label("Ouvrir dans Plans", systemImage: "map")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(Theme.readableAccent)
                }
                .buttonStyle(.borderless)
                .padding(.horizontal, 16)
                .padding(.top, 8)
                .padding(.bottom, 12)
                .accessibilityIdentifier("field.location.open.\(field.id)")
            }
        }
    }
}

/// Barcode: value as text, format, "Afficher en grand" with the generated image.
private struct BarcodeRow: View {
    let field: FfiField
    let value: String
    let format: FfiBarcodeFormat
    let onCopy: () -> Void
    @State private var large = false

    var body: some View {
        DetailRow(
            label: field.displayLabel.detailLabelCase, copyIdentifier: "field.copy.\(field.id)", onCopy: onCopy,
            showsMenu: true
        ) {
            VStack(alignment: .leading, spacing: 2) {
                Text(value).font(.body.monospaced())
                Text(BarcodeRenderer.name(format)).font(.caption).foregroundStyle(.secondary)
            }
        } accessory: {
            EmptyView()
        } menu: {
            Button("Afficher en grand", systemImage: "barcode.viewfinder") { large = true }
        }
        .sheet(isPresented: $large) {
            BarcodeLargeView(label: field.displayLabel, value: value, format: format)
        }
    }
}

/// A website of the item, under the fields card: label ("site web" by default) and the link, which
/// opens in the browser. Copier on hover (Mac) or as an icon (elsewhere).
struct WebsiteRow: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    let url: FfiUrl
    let index: Int
    let onCopied: (String) -> Void
    @State private var hovered = false
    #if os(iOS)
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var copies = 0
    @State private var showsCopied = false
    #endif

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                EditorLabel(url.label.isEmpty ? String(localized: "site web") : url.label.detailLabelCase)
                if let target = FieldValueView.openable(url.url) {
                    Button {
                        openURL(target)
                    } label: {
                        Text(url.url)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .foregroundStyle(Theme.readableAccent)
                            .underline(hovered)
                    }
                    .buttonStyle(.plain)
                    #if os(macOS)
                    .pointerStyle(.link)
                    #endif
                    .accessibilityHint(Text("Ouvrir"))
                    .accessibilityIdentifier("item.url.open.\(index)")
                } else {
                    Text(url.url).lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer(minLength: 0)
            Button(action: copy) {
                #if os(macOS)
                Text("Copier").font(.callout.weight(.medium)).foregroundStyle(Theme.readableAccent)
                #elseif os(iOS)
                Image(systemName: showsCopied ? "checkmark" : "doc.on.doc")
                    .contentTransition(reduceMotion ? .opacity : .symbolEffect(.replace))
                    .frame(width: 44, height: 44)
                    .contentShape(.rect)
                #else
                Image(systemName: "doc.on.doc")
                #endif
            }
            .buttonStyle(.borderless)
            #if os(macOS)
            .opacity(hovered ? 1 : 0)
            #elseif os(iOS)
            .padding(.vertical, -10)
            .padding(.trailing, -10)
            .sensoryFeedback(.success, trigger: copies)
            .task(id: copies) {
                guard copies > 0 else { return }
                try? await Task.sleep(for: Motion.copiedHold)
                guard !Task.isCancelled else { return }
                showsCopied = false
            }
            #endif
            .accessibilityLabel(Text("Copier"))
            .accessibilityIdentifier("item.url.copy.\(index)")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 6)
        .contentShape(.rect)
        #if os(macOS)
        .onHover { inside in
            withAnimation(.easeOut(duration: 0.12)) { hovered = inside }
        }
        #endif
    }

    private func copy() {
        model.session.copy(url.url, concealed: false)
        onCopied(String(localized: "Copié · effacé dans 90 s"))
        #if os(iOS)
        copies += 1
        showsCopied = true
        #endif
    }
}
