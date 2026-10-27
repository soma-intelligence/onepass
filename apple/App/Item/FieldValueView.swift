import DesignKit
import SwiftUI
import VaultKit

/// One non-empty field in the detail view, drawn for its kind. Secrets are masked (`FieldRow`,
/// 30 s re-mask, masked again on lock and when the scene leaves the foreground, kept masked while
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
    /// Tells the detail a value was copied (toast).
    let onCopied: (String) -> Void

    private var session: VaultSession { model.session }

    var body: some View {
        switch field.value {
        case .otp(let secret):
            TotpFieldView(field: field, captured: captured) { code in copy(code, concealed: true) }
                .id(secret)
                .privacySensitive()
        case .password(let value):
            VStack(alignment: .leading, spacing: 6) {
                row(value, secret: true, monospaced: true)
                StrengthMeter(bits: PasswordStrength.estimatedBits(value))
            }
        case .concealed(let value), .mnemonic(let value):
            row(value, secret: true, monospaced: true)
        case .url(let value):
            urlRow(label: field.label, url: value, identifier: "field.copy.\(field.id)")
        case .text(let v), .email(let v), .phone(let v), .menu(let v):
            row(v, secret: false, monospaced: false)
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
            row(LocationEditor.summary(l), secret: false, monospaced: false)
        case .sshKey(let key):
            VStack(alignment: .leading, spacing: 8) {
                if !key.privatePem.isEmpty {
                    FieldRow(
                        label: "\(field.label) (clé privée)", value: key.privatePem, isSecret: true, monospaced: true,
                        copyIdentifier: "field.copy.\(field.id)", allowsLarge: false,
                        concealToken: session.concealGeneration, captured: captured,
                        onCopy: { copy(key.privatePem, concealed: true) }, onReveal: reveal)
                        .privacySensitive()
                }
                if !key.publicOpenssh.isEmpty {
                    FieldRow(
                        label: "Clé publique", value: key.publicOpenssh, isSecret: false, monospaced: true,
                        copyIdentifier: "field.copy.\(field.id).public", allowsLarge: false,
                        onCopy: { copy(key.publicOpenssh, concealed: false) }, onReveal: nil)
                }
                if !key.fingerprintSha256.isEmpty {
                    FieldRow(
                        label: "Empreinte", value: key.fingerprintSha256, isSecret: false, monospaced: true,
                        allowsLarge: false, onCopy: { copy(key.fingerprintSha256, concealed: false) }, onReveal: nil)
                }
            }
        case .barcode(let value, let format):
            BarcodeRow(field: field, value: value, format: format) { copy(value, concealed: false) }
        case .itemLink(let id):
            itemLinkRow(id)
        case .passkey(let passkey):
            PasskeyRow(field: field, passkey: passkey)
        case .file:
            VStack(alignment: .leading, spacing: 2) {
                Text(field.label).font(.footnote).foregroundStyle(.secondary)
                ReadOnlyFieldView(field: field)
            }
        case .empty:
            EmptyView()
        }
    }

    private func row(_ value: String, secret: Bool, monospaced: Bool) -> some View {
        let session = session
        let onReveal: ((Bool) -> Void)? = secret ? { _ in session.noteActivity() } : nil
        return FieldRow(
            label: field.label, value: value, isSecret: secret, monospaced: monospaced,
            copyIdentifier: "field.copy.\(field.id)",
            // "Afficher en grand" for passwords (barcodes have their own row).
            allowsLarge: field.kind == .password,
            concealToken: session.concealGeneration, captured: captured,
            onCopy: { copy(value, concealed: secret) },
            onReveal: onReveal)
            .privacySensitive(secret)
    }

    private func reveal(_ shown: Bool) {
        session.noteActivity()
    }

    private func copy(_ value: String, concealed: Bool) {
        session.copy(value, concealed: concealed)
        onCopied(String(localized: "Copié · effacé dans 90 s"))
    }

    private func urlRow(label: String, url: String, identifier: String) -> some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.footnote).foregroundStyle(.secondary)
                Text(url).lineLimit(1).truncationMode(.middle).foregroundStyle(.tint)
            }
            Spacer(minLength: 0)
            if let target = Self.openable(url) {
                Button {
                    openURL(target)
                } label: {
                    Image(systemName: "arrow.up.forward.app")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(Text("Ouvrir"))
            }
            Button {
                copy(url, concealed: false)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(Text("Copier"))
            .accessibilityIdentifier(identifier)
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
        VStack(alignment: .leading, spacing: 2) {
            Text(field.label).font(.footnote).foregroundStyle(.secondary)
            if let linked {
                Button {
                    model.editing = false
                    model.selectedItem = ItemRef(vaultID: linked.vaultId, itemID: linked.id)
                } label: {
                    Label(linked.title, systemImage: "link")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("field.link.\(field.id)")
            } else {
                Text("Élément introuvable").foregroundStyle(.secondary)
            }
        }
    }
}

/// A passkey of a Login (spec 6): the site it signs in to, the account name and the creation date.
/// Nothing secret: the private key never leaves the core.
private struct PasskeyRow: View {
    let field: FfiField
    let passkey: FfiPasskey

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "person.badge.key.fill")
                .font(.title3)
                .foregroundStyle(.tint)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(field.label).font(.footnote).foregroundStyle(.secondary)
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
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("field.passkey.\(field.id)")
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
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(field.label).font(.footnote).foregroundStyle(.secondary)
                Text(value).font(.body.monospaced())
                Text(BarcodeRenderer.name(format)).font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            Menu {
                Button("Copier", systemImage: "doc.on.doc", action: onCopy)
                    .accessibilityIdentifier("field.copy.\(field.id)")
                Button("Afficher en grand", systemImage: "barcode.viewfinder") { large = true }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .accessibilityLabel(Text("Actions pour \(field.label)"))
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .sheet(isPresented: $large) {
            BarcodeLargeView(label: field.label, value: value, format: format)
        }
    }
}

/// A website of the item: label ("site web" by default), URL, Ouvrir, Copier.
struct WebsiteRow: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    let url: FfiUrl
    let index: Int
    let onCopied: (String) -> Void

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(url.label.isEmpty ? String(localized: "site web") : url.label)
                    .font(.footnote).foregroundStyle(.secondary)
                Text(url.url).lineLimit(1).truncationMode(.middle).foregroundStyle(.tint)
            }
            Spacer(minLength: 0)
            if let target = FieldValueView.openable(url.url) {
                Button {
                    openURL(target)
                } label: {
                    Image(systemName: "arrow.up.forward.app")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(Text("Ouvrir"))
                .accessibilityIdentifier("item.url.open.\(index)")
            }
            Button {
                model.session.copy(url.url, concealed: false)
                onCopied(String(localized: "Copié · effacé dans 90 s"))
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(Text("Copier"))
            .accessibilityIdentifier("item.url.copy.\(index)")
        }
    }
}
