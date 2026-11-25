import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// Réglages > Suggérer une fonctionnalité: the person picks what kind of message it is, types it,
/// may leave an email, and Envoyer sends it to Soma Labs (`FeatureRequestClient`, unchanged).
/// Laid out as a friendly page rather than a bare form: a header that says why we ask, the kind as
/// chips, the text on its own card with a counter, one large Envoyer at the bottom, then a thank
/// you screen. Nothing from the vault is read or sent. On an error the text stays, so nothing
/// typed is lost.
struct FeatureRequestSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var message = ""
    @State private var email = ""
    @State private var kind = Kind.idea
    @State private var phase = Phase.editing
    @State private var failure: FeatureRequestError?
    @FocusState private var focus: Field?

    var client = FeatureRequestClient()

    enum Phase: Equatable {
        case editing, sending, sent
    }

    private enum Field: Hashable { case message, email }

    /// What the message is about. The request has no field for it and its call stays as it is,
    /// so the kind travels as a short English tag in front of the text ("[bug] …"): stable
    /// whatever the app's language, and easy to sort on the Soma Labs side.
    enum Kind: String, CaseIterable, Identifiable {
        case idea, improvement, bug, other
        var id: String { rawValue }
        var title: LocalizedStringKey { LocalizedStringKey("featureRequest.kind." + rawValue) }
        var symbol: String {
            switch self {
            case .idea: "lightbulb"
            case .improvement: "wand.and.sparkles"
            case .bug: "ladybug"
            case .other: "ellipsis.bubble"
            }
        }
        var tag: String { "[\(rawValue)] " }
    }

    static let table = "FeatureRequest"
    /// How long the thank-you screen stays before the sheet closes: long enough to read it.
    private static let thanksDelay: Duration = .seconds(2.2)
    /// The tag goes in front of the text, so the text keeps room for the longest tag.
    private static let messageLimit = FeatureRequestClient.maximumLength - Kind.allCases.map(\.tag.count).max()!
    /// From here the counter turns orange, so the limit never comes as a surprise.
    private static let counterWarning = messageLimit - 200

    private typealias RX = Theme.RX

    private var canSend: Bool { phase == .editing && FeatureRequestClient.canSend(message) }

    var body: some View {
        NavigationStack {
            Group {
                if phase == .sent {
                    thanks
                        .transition(.opacity.combined(with: .scale(scale: 0.96)))
                } else {
                    form
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(RX.Palette.pageBackground.color)
            .navigationTitle(Text("featureRequest.title", tableName: Self.table))
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                if phase != .sent {
                    ToolbarItem(placement: .cancellationAction) {
                        Button(role: .close) { dismiss() }
                            .disabled(phase == .sending)
                            .accessibilityIdentifier("settings.featureRequest.cancel")
                    }
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 460, minHeight: 560)
        #endif
        .interactiveDismissDisabled(phase == .sending)
        .dbHaptic(.success, trigger: phase == .sent)
        .animation(.smooth, value: phase)
        .onChange(of: message) {
            if message.count > Self.messageLimit {
                message = String(message.prefix(Self.messageLimit))
            }
            if failure == .messageTooShort || failure == .messageTooLong { failure = nil }
        }
        .onChange(of: email) {
            if failure == .invalidEmail { failure = nil }
        }
        // No focus on appear: the keyboard would push the header away, and the header is what
        // makes the page feel inviting. One tap on the card starts typing.
        .task(id: phase) {
            guard phase == .sent else { return }
            try? await Task.sleep(for: Self.thanksDelay)
            dismiss()
        }
    }

    // MARK: Form

    private var form: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: RX.Space.xl) {
                header
                kinds
                VStack(alignment: .leading, spacing: RX.Space.m) {
                    messageCard
                    emailField
                    if let failure {
                        errorBanner(failure)
                            .transition(.move(edge: .top).combined(with: .opacity))
                    }
                    privacyNote
                }
            }
            .padding(.horizontal, RX.Space.gutter)
            .padding(.top, RX.Space.s)
            .padding(.bottom, RX.Space.xl)
            .animation(.snappy, value: failure)
        }
        .scrollDismissesKeyboard(.interactively)
        // Envoyer stays in reach above the keyboard, the one action of the page.
        .safeAreaInset(edge: .bottom) { sendBar }
    }

    /// A lit symbol and two lines that say what this is for, so the page feels like an
    /// invitation rather than a support form.
    private var header: some View {
        VStack(spacing: RX.Space.m) {
            ZStack {
                Circle()
                    .fill(RX.Palette.accentSoft.color)
                    .frame(width: 72, height: 72)
                Image(systemName: "lightbulb.max.fill")
                    .font(.system(size: 32, weight: .semibold))
                    .foregroundStyle(RX.Palette.accent.color)
                    .symbolEffect(.bounce, options: .nonRepeating)
            }
            .accessibilityHidden(true)
            VStack(spacing: RX.Space.xs) {
                Text("featureRequest.header.title")
                    .rxFont(.title)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                Text("featureRequest.header.subtitle")
                    .rxFont(.callout)
                    .foregroundStyle(RX.Palette.textSecondary.color)
            }
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, RX.Space.s)
    }

    private var kinds: some View {
        VStack(alignment: .leading, spacing: RX.Space.s) {
            Text("featureRequest.kind.title")
                .rxFont(.footnoteBold)
                .foregroundStyle(RX.Palette.textSecondary.color)
                .padding(.leading, RX.Space.xs)
            FlowLayout(spacing: RX.Space.s) {
                ForEach(Kind.allCases) { item in
                    Button {
                        withAnimation(.snappy) { kind = item }
                    } label: {
                        RXChip(Text(item.title), selected: kind == item) {
                            Image(systemName: item.symbol)
                                .font(.footnote.weight(.semibold))
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(phase != .editing)
                    .accessibilityIdentifier("settings.featureRequest.kind.\(item.rawValue)")
                }
            }
        }
        .sensoryFeedback(.selection, trigger: kind)
    }

    /// The text on its own card, the counter in its corner: one glance tells how much room is left.
    private var messageCard: some View {
        VStack(alignment: .trailing, spacing: RX.Space.s) {
            TextField(text: $message, prompt: Text("featureRequest.message.prompt", tableName: Self.table),
                      axis: .vertical) {
                Text("featureRequest.message.label", tableName: Self.table)
            }
            .rxFont(.body)
            .lineLimit(6 ... 12)
            .focused($focus, equals: .message)
            .disabled(phase != .editing)
            .accessibilityLabel(Text("featureRequest.message.label", tableName: Self.table))
            .accessibilityIdentifier("settings.featureRequest.message")
            Text("featureRequest.count \(message.count)", tableName: Self.table)
                .rxFont(.caption)
                .monospacedDigit()
                .foregroundStyle(message.count >= Self.counterWarning
                                 ? RX.Palette.warning.color : RX.Palette.textTertiary.color)
                .contentTransition(.numericText())
                .accessibilityLabel(Text("featureRequest.count.a11y \(message.count)", tableName: Self.table))
                .accessibilityIdentifier("settings.featureRequest.count")
        }
        .padding(RX.Space.l)
        .background(RX.Palette.cardBackground.color, in: .rect(cornerRadius: RX.Radius.card, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous)
                .strokeBorder(focus == .message ? RX.Palette.accent.color.opacity(0.6) : .clear, lineWidth: 1.5)
        }
        .animation(.snappy, value: focus)
        .contentShape(.rect)
        .onTapGesture { focus = .message }
    }

    private var emailField: some View {
        HStack(spacing: RX.Space.m) {
            Image(systemName: "envelope")
                .foregroundStyle(RX.Palette.textTertiary.color)
                .accessibilityHidden(true)
            TextField(text: $email, prompt: Text("featureRequest.email.prompt", tableName: Self.table)) {
                Text("featureRequest.email.label", tableName: Self.table)
            }
            .rxFont(.body)
            .textContentType(.emailAddress)
            #if os(iOS) || os(visionOS)
            .keyboardType(.emailAddress)
            .textInputAutocapitalization(.never)
            #endif
            .autocorrectionDisabled()
            .focused($focus, equals: .email)
            .disabled(phase != .editing)
            .submitLabel(.send)
            .onSubmit(send)
            .accessibilityLabel(Text("featureRequest.email.label", tableName: Self.table))
            .accessibilityIdentifier("settings.featureRequest.email")
        }
        .padding(.horizontal, RX.Space.l)
        .frame(minHeight: RX.Metrics.minTapTarget + RX.Space.s)
        .background(RX.Palette.cardBackground.color, in: .rect(cornerRadius: RX.Radius.tile, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: RX.Radius.tile, style: .continuous)
                .strokeBorder(focus == .email ? RX.Palette.accent.color.opacity(0.6) : .clear, lineWidth: 1.5)
        }
        .animation(.snappy, value: focus)
    }

    private var privacyNote: some View {
        Label {
            Text("featureRequest.footer", tableName: Self.table)
        } icon: {
            Image(systemName: "lock.fill")
                .accessibilityHidden(true)
        }
        .rxFont(.footnote)
        .foregroundStyle(RX.Palette.textSecondary.color)
        .padding(.horizontal, RX.Space.xs)
    }

    private func errorBanner(_ failure: FeatureRequestError) -> some View {
        Label {
            Text(Self.errorKey(failure), tableName: Self.table)
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill")
                .accessibilityHidden(true)
        }
        .rxFont(.callout)
        .foregroundStyle(RX.Palette.negative.color)
        .padding(RX.Space.m)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RX.Palette.negative.color.opacity(0.1), in: .rect(cornerRadius: RX.Radius.tile, style: .continuous))
        .accessibilityIdentifier("settings.featureRequest.error")
    }

    /// One full width Envoyer, disabled until there is something to send; a spinner while it goes.
    private var sendBar: some View {
        Button(action: send) {
            HStack(spacing: RX.Space.s) {
                if phase == .sending {
                    ProgressView()
                        .tint(RX.Palette.onAccent.color)
                        .accessibilityLabel(Text("featureRequest.sending", tableName: Self.table))
                        .accessibilityIdentifier("settings.featureRequest.sending")
                } else {
                    Image(systemName: "paperplane.fill")
                        .accessibilityHidden(true)
                }
                Text(sendTitle, tableName: Self.table)
            }
            .rxFont(.bodyMedium)
            .frame(maxWidth: .infinity, minHeight: RX.Metrics.minTapTarget + RX.Space.xs)
        }
        .buttonStyle(.glassProminent)
        .tint(RX.Palette.accent.color)
        .disabled(!canSend)
        .keyboardShortcut(.defaultAction)
        .padding(.horizontal, RX.Space.gutter)
        .padding(.vertical, RX.Space.s)
        // The page fades in under the bar, so text scrolled behind Envoyer never fights its label.
        .background {
            LinearGradient(colors: [RX.Palette.pageBackground.color.opacity(0), RX.Palette.pageBackground.color],
                           startPoint: .top, endPoint: .center)
                .ignoresSafeArea()
        }
        .accessibilityIdentifier("settings.featureRequest.send")
    }

    private var sendTitle: LocalizedStringKey {
        phase == .sending ? "featureRequest.sending" : "featureRequest.send"
    }

    // MARK: Thanks

    private var thanks: some View {
        VStack(spacing: RX.Space.l) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 64, weight: .semibold))
                .symbolRenderingMode(.palette)
                .foregroundStyle(.white, RX.Palette.positive.color)
                .symbolEffect(.bounce, options: .nonRepeating)
                .accessibilityHidden(true)
            VStack(spacing: RX.Space.xs) {
                Text("featureRequest.sent.title")
                    .rxFont(.title)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                Text("featureRequest.sent", tableName: Self.table)
                    .rxFont(.callout)
                    .foregroundStyle(RX.Palette.textSecondary.color)
            }
            .multilineTextAlignment(.center)
        }
        .padding(RX.Space.xl)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("settings.featureRequest.sent")
    }

    private func send() {
        guard canSend else { return }
        failure = nil
        focus = nil
        phase = .sending
        let idea = FeatureRequest.current(message: kind.tag + message, email: email)
        Task {
            do throws(FeatureRequestError) {
                try await client.send(idea)
                phase = .sent
            } catch {
                failure = error
                phase = .editing
            }
        }
    }

    static func errorKey(_ error: FeatureRequestError) -> LocalizedStringKey {
        switch error {
        case .messageTooShort: "featureRequest.error.tooShort"
        case .messageTooLong: "featureRequest.error.tooLong"
        case .invalidEmail: "featureRequest.error.invalidEmail"
        case .rateLimited: "featureRequest.error.rateLimited"
        case .server: "featureRequest.error.server"
        case .network: "featureRequest.error.network"
        }
    }
}
