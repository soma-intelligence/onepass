import DesignKit
import SwiftUI
import VaultKit

/// The body of the current step, shared by the iPhone, iPad and Mac layouts.
struct OnboardingStepContent: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        VStack(alignment: .leading, spacing: Platform.isMac ? 18 : 22) {
            switch model.step {
            case .welcome: WelcomeStep(model: model)
            case .device: DeviceStep(model: model)
            case .password: PasswordStep(model: model)
            case .secretKey: SecretKeyStep(model: model)
            case .biometrics: BiometricsStep(model: model)
            case .visibleVaults: VisibleVaultsStep(model: model)
            case .restore: RestoreStep(model: model)
            case .done: DoneStep(model: model)
            case .pairMode: PairingModeStep(model: model)
            case .pairing: PairingStep(model: model)
            }
            // iPhone and iPad: the primary button carries the busy message.
            if Platform.isMac, let busy = model.busyMessage {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(busy).foregroundStyle(.secondary)
                }
                .font(.subheadline)
            }
            if let error = model.errorMessage {
                OnboardingErrorCard(message: error, model: model)
                    .transition(.opacity.combined(with: .offset(y: 6)))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .animation(.smooth(duration: 0.3), value: model.errorMessage)
        .disabled(model.busy)
    }
}

/// An error where it happened, with its next step as a button: never only an alert.
private struct OnboardingErrorCard: View {
    let message: String
    let model: OnboardingModel

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.body.weight(.semibold))
                .foregroundStyle(.red)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 10) {
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("onboarding.error")
                if let action = model.errorAction {
                    Button(action.label) { Task { await model.performErrorAction() } }
                        .font(.subheadline.weight(.semibold))
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("onboarding.errorAction")
                }
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background {
            let shape = RoundedRectangle(cornerRadius: Platform.isMac ? 12 : 16, style: .continuous)
            shape.fill(Color.red.opacity(0.08))
                .overlay(shape.strokeBorder(Color.red.opacity(0.22), lineWidth: 1))
        }
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Shared pieces

struct StepTitle: View {
    let title: LocalizedStringResource
    let subtitle: LocalizedStringResource?
    var centered = false

    var body: some View {
        VStack(alignment: centered ? .center : .leading, spacing: Platform.isMac ? 10 : 12) {
            Text(title)
                .font(Platform.isMac ? .system(size: 28, weight: .bold) : .largeTitle.bold())
                .multilineTextAlignment(centered ? .center : .leading)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            if let subtitle {
                Text(subtitle)
                    .font(Platform.isMac ? .system(size: 15) : .body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(centered ? .center : .leading)
                    .lineSpacing(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: centered ? .center : .leading)
    }
}

enum Platform {
    #if os(macOS)
    static let isMac = true
    #else
    static let isMac = false
    #endif

    /// The Mac or the iPhone and iPad variant of a text (both literals reach the string catalog).
    static func text(mac: LocalizedStringResource, phone: LocalizedStringResource) -> LocalizedStringResource {
        isMac ? mac : phone
    }

    /// The Secret Key entry text: typed only on Mac and Vision Pro (no camera access for apps).
    static func secretKeyText(mac: LocalizedStringResource, phone: LocalizedStringResource) -> LocalizedStringResource {
        #if os(visionOS)
        mac
        #else
        text(mac: mac, phone: phone)
        #endif
    }

    /// "iPhone", "iPad", "Apple Vision Pro" or "Mac", for texts.
    @MainActor static var deviceName: String {
        #if os(macOS)
        "Mac"
        #elseif os(visionOS)
        "Apple Vision Pro"
        #else
        UIDevice.current.userInterfaceIdiom == .pad ? "iPad" : "iPhone"
        #endif
    }
}

/// Rounded card background: grouped fill on iPhone and iPad, outlined on Mac (mockups).
private struct CardBackground: ViewModifier {
    var selected = false

    func body(content: Content) -> some View {
        content
            .background {
                let shape = RoundedRectangle(cornerRadius: Platform.isMac ? 14 : 16, style: .continuous)
                if Platform.isMac {
                    shape.fill(Color.primary.opacity(0.03))
                        .overlay(shape.strokeBorder(selected ? Theme.accent : Color.primary.opacity(0.1),
                                                    lineWidth: selected ? 2 : 1))
                } else {
                    shape.fill(selected ? AnyShapeStyle(Theme.accent.opacity(0.10)) : AnyShapeStyle(.fill.tertiary))
                        .overlay(shape.strokeBorder(selected ? Theme.accent : .clear, lineWidth: 2))
                }
            }
    }
}

extension View {
    func card(selected: Bool = false) -> some View { modifier(CardBackground(selected: selected)) }

    /// A card that acts as a button: it gives a little under the finger on iPhone.
    @ViewBuilder func onboardingPressable() -> some View {
        #if os(iOS)
        buttonStyle(PressableButtonStyle())
        #else
        buttonStyle(.plain)
        #endif
    }
}

/// The fields of a step that pass the focus along (return goes to the next one).
enum OnboardingFocus: Hashable {
    case password, confirm
}

/// Text or secure field in the mockup style (filled on iPhone, bordered on Mac).
struct OnboardingField: View {
    let label: LocalizedStringResource
    let prompt: LocalizedStringResource
    @Binding var text: String
    var secure = false
    var mismatch = false
    /// Checked and right (a confirmation that matches): green outline and check.
    var valid = false
    var monospaced = false
    /// Secret Key entry: no autocorrection, ASCII keyboard, capitals, hidden from screen captures.
    var secretKey = false
    var identifier: String
    /// Focus chaining (secure fields): the step's focused field and this field's place in it. A
    /// plain binding, not `@FocusState`: the UIKit secure field is not a SwiftUI focusable view,
    /// so a focus state pointing at it would be reset.
    var focus: Binding<OnboardingFocus?>?
    var focusValue: OnboardingFocus?
    /// Return of a secure field: passed to the field itself, since it is UIKit on iOS and SwiftUI's
    /// `.onSubmit` and `.focused` never reach it (Return used to do nothing there). Text fields
    /// keep their callers' `.onSubmit`.
    var submitNext = false
    var onSubmit: () -> Void = {}

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.subheadline).foregroundStyle(.secondary)
            Group {
                if secure {
                    // Emptied as it leaves the screen: iOS never offers to save the master password.
                    SecretInputField(
                        title: String(localized: prompt), text: $text, focused: secureFocus,
                        submitNext: submitNext, onSubmit: onSubmit, identifier: identifier)
                } else {
                    TextField(text: $text, prompt: Text(prompt)) { Text(label) }
                }
            }
            .labelsHidden()
            .textFieldStyle(.plain)
            .font(monospaced ? .system(.body, design: .monospaced) : .body)
            .autocorrectionDisabled()
            #if os(iOS) || os(visionOS)
            .textInputAutocapitalization(secretKey ? .characters : .never)
            .keyboardType(secretKey ? .asciiCapable : .default)
            #endif
            .privacySensitive(secretKey || secure)
            .accessibilityIdentifier(identifier)
            .padding(.leading, 14)
            .padding(.trailing, mismatch || valid ? 8 : 14)
            .frame(height: Platform.isMac ? 40 : 52)
            .overlay(alignment: .trailing) {
                if mismatch || valid {
                    Image(systemName: valid ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(valid ? Color.green : Color.red)
                        .padding(.trailing, 12)
                        .transition(.scale(scale: 0.6).combined(with: .opacity))
                        .accessibilityHidden(true)
                }
            }
            .background {
                let shape = RoundedRectangle(cornerRadius: Platform.isMac ? 10 : 14, style: .continuous)
                let edge: Color = mismatch ? .red : valid ? .green : .clear
                if Platform.isMac {
                    shape.fill(.background)
                        .overlay(shape.strokeBorder(edge == .clear ? Color.primary.opacity(0.15) : edge,
                                                    lineWidth: edge == .clear ? 1 : 2))
                } else {
                    shape.fill(.fill.tertiary)
                        .overlay(shape.strokeBorder(edge, lineWidth: 1.5))
                }
            }
            .animation(.smooth(duration: 0.2), value: mismatch)
            .animation(.smooth(duration: 0.2), value: valid)
        }
    }
}

extension OnboardingField {
    /// The step's focus seen from one secure field: on when the focus is this field's value.
    private var secureFocus: Binding<Bool>? {
        guard let focus, let focusValue else { return nil }
        return Binding(
            get: { focus.wrappedValue == focusValue },
            set: { on in
                if on {
                    focus.wrappedValue = focusValue
                } else if focus.wrappedValue == focusValue {
                    focus.wrappedValue = nil
                }
            })
    }
}

private struct CheckRow: View {
    let title: LocalizedStringResource
    @Binding var isOn: Bool

    var body: some View {
        #if os(macOS)
        Toggle(isOn: $isOn) { Text(title) }.toggleStyle(.checkbox)
        #else
        Button {
            isOn.toggle()
        } label: {
            HStack(spacing: 10) {
                Image(systemName: isOn ? "checkmark.square.fill" : "square")
                    .font(.title3)
                    .foregroundStyle(isOn ? Theme.accent : .secondary)
                Text(title).foregroundStyle(.primary)
            }
        }
        .buttonStyle(.plain)
        .visionHoverEffect()
        .accessibilityAddTraits(isOn ? .isSelected : [])
        #endif
    }
}

// MARK: - Bienvenue

private struct WelcomeStep: View {
    let model: OnboardingModel

    var body: some View {
        if Platform.isMac {
            AppGlyph(size: 64).accessibilityHidden(true)
        } else {
            AppGlyph(size: 88).padding(.top, 28).padding(.bottom, 2)
        }
        VStack(alignment: .leading, spacing: 6) {
            Text("onboarding.welcomeToOnepass")
                .font(.system(size: Platform.isMac ? 32 : 34, weight: .bold))
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            Text("onboarding.welcome.howToStart")
                .font(Platform.isMac ? .system(size: 15) : .system(size: 17))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        VStack(spacing: 14) {
            createButton
            VStack(spacing: 0) {
                row(
                    "onboarding.welcome.restore", "onboarding.welcome.restoreDetail", symbol: "doc.text",
                    identifier: "onboarding.restore"
                ) { model.choose(.restore) }
                Divider().padding(.leading, 62)
                row(
                    "onboarding.welcome.pair", "onboarding.welcome.pairDetail", symbol: "qrcode",
                    identifier: "onboarding.pair"
                ) { model.choose(.pair) }
            }
            .card()
        }
        .padding(.top, 10)
    }

    /// The first-time path, the one most people take: full width, in the accent wash.
    private var createButton: some View {
        Button { model.choose(.create) } label: {
            HStack(spacing: 14) {
                Image(systemName: "plus")
                    .font(.system(size: 17, weight: .bold))
                    .frame(width: 34, height: 34)
                    .background(.white.opacity(0.2), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    Text("onboarding.welcome.create")
                        .font(.system(size: Platform.isMac ? 16 : 17, weight: .semibold))
                    Text("onboarding.welcome.createDetail")
                        .font(.system(size: 13.5))
                        .opacity(0.85)
                }
                .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
                Image(systemName: "arrow.right").font(.body.weight(.semibold))
            }
            .foregroundStyle(.white)
            .padding(.horizontal, 18)
            .padding(.vertical, 16)
            .frame(maxWidth: .infinity)
            .background {
                Color.clear.washBackground(
                    Theme.Wash.accent, flat: Theme.accent,
                    in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            }
            .contentShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        }
        .onboardingPressable()
        .visionHoverEffect()
        .accessibilityIdentifier("onboarding.create")
    }

    private func row(
        _ title: LocalizedStringResource, _ subtitle: LocalizedStringResource, symbol: String,
        identifier: String, action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: symbol)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 32, height: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: Platform.isMac ? 14.5 : 16, weight: .medium))
                    Text(subtitle).font(.system(size: 13)).foregroundStyle(.secondary)
                }
                .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 13)
            .contentShape(Rectangle())
        }
        .onboardingPressable()
        .visionHoverEffect()
        .accessibilityIdentifier(identifier)
    }
}

// MARK: - Type d'appareil

private struct DeviceStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        StepTitle(
            title: Platform.isMac ? "Ce Mac est-il à toi ?" : "Cet appareil est-il à toi ?",
            subtitle: "La réponse règle ce que OnePass garde sur cet appareil.")
        VStack(spacing: 10) {
            option(
                .personal, "Oui, il est à moi",
                "Personnel. Déverrouillage par \(model.biometryName), verrouillage automatique réglable.")
            option(
                .shared, "Il est partagé",
                "Appareil de la famille ou du bureau. Pas de \(model.biometryName), verrouillage après 5 min, coffres visibles au choix.")
        }
        if model.mailboxSignupEnabled {
            Button("onboarding.syncChoice.link") { model.showSyncChoice = true }
                .buttonStyle(.borderless)
                .font(.footnote)
                .accessibilityIdentifier("onboarding.syncChoice")
                .sheet(isPresented: $model.showSyncChoice) {
                    SyncChoiceSheet(choice: $model.syncChoice)
                }
        }
    }

    private func option(
        _ mode: DeviceMode, _ title: LocalizedStringResource, _ subtitle: LocalizedStringResource
    ) -> some View {
        let selected = model.mode == mode
        return Button {
            withAnimation(.spring(duration: 0.35, bounce: 0.15)) { model.mode = mode }
        } label: {
            HStack(spacing: 14) {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(selected ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.fill.secondary))
                    .frame(width: 44, height: 44)
                    .overlay {
                        Image(systemName: mode == .personal ? "person.fill" : "person.2.fill")
                            .font(.system(size: 18, weight: .semibold))
                            .foregroundStyle(selected ? Color.white : Color.primary)
                    }
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.system(size: 16, weight: .semibold))
                    Text(subtitle).font(.system(size: 13.5)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
                ZStack {
                    Circle()
                        .strokeBorder(Color.secondary.opacity(selected ? 0 : 0.35), lineWidth: 1.5)
                    if selected {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 24))
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, Theme.accent)
                            .transition(.scale(scale: 0.4).combined(with: .opacity))
                    }
                }
                .frame(width: 24, height: 24)
                .accessibilityHidden(true)
            }
            .padding(16)
            .contentShape(Rectangle())
            .card(selected: selected)
            .scaleEffect(selected || Platform.isMac ? 1 : 0.98)
            .opacity(selected || Platform.isMac ? 1 : 0.9)
        }
        .onboardingPressable()
        .visionHoverEffect()
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier(mode == .personal ? "onboarding.personal" : "onboarding.shared")
    }
}

// MARK: - Mot de passe maître

private struct PasswordStep: View {
    @Bindable var model: OnboardingModel
    @State private var focus: OnboardingFocus?

    var body: some View {
        StepTitle(
            title: Platform.isMac ? "Choisis ton mot de passe maître" : "Ton mot de passe maître",
            subtitle: Platform.text(
                mac: "onboarding.onlyPasswordNeedTo",
                phone: "Le seul à retenir. Personne ne peut le récupérer pour toi."))
        #if os(macOS)
        OnboardingField(
            label: "Ton prénom (affiché seulement sur tes appareils)", prompt: "Camille",
            text: $model.displayName, identifier: "onboarding.name")
        #endif
        VStack(alignment: .leading, spacing: 10) {
            OnboardingField(
                label: "Mot de passe maître",
                prompt: Platform.isMac ? "Cinq mots tirés au hasard marchent bien" : "Cinq mots tirés au hasard",
                text: $model.password, secure: true, identifier: "onboarding.password",
                focus: $focus, focusValue: .password, submitNext: true, onSubmit: { focus = .confirm })
            MasterStrengthMeter(password: model.password, bits: model.passwordBits)
        }
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Button {
                withAnimation(.smooth(duration: 0.3)) { model.generateMasterPassword() }
            } label: {
                Label("Générer", systemImage: "wand.and.stars")
            }
            .buttonStyle(.glass)
            .accessibilityIdentifier("onboarding.generate")
            if let generated = model.generatedPassword, generated == model.password {
                Text(verbatim: generated)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .privacySensitive()
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("onboarding.generated")
            }
        }
        VStack(alignment: .leading, spacing: 8) {
            OnboardingField(
                label: "Confirme-le", prompt: "", text: $model.confirmation, secure: true,
                mismatch: model.confirmationMismatch, valid: model.confirmationMatches,
                identifier: "onboarding.confirm", focus: $focus, focusValue: .confirm,
                onSubmit: { Task { await model.primary() } })
            if model.confirmationMismatch {
                Label("app.twoEntriesDontMatch", systemImage: "xmark")
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(.red)
                    .transition(.opacity)
                    .accessibilityIdentifier("onboarding.mismatch")
            }
        }
        .id(OnboardingFocus.confirm)
        .animation(.smooth(duration: 0.2), value: model.confirmationMismatch)
        PasswordRulesList(rules: model.passwordRules)
        if Platform.isMac {
            Label {
                Text("onboarding.tipFiveRandomWords")
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "lightbulb")
            }
            .font(.system(size: 13))
            .foregroundStyle(.secondary)
            .padding(12)
            .card()
        }
    }
}

/// Live strength of the master password, on the scale of the gate: green only once it passes.
private struct MasterStrengthMeter: View {
    let password: String
    let bits: Double

    private var level: Int {
        if password.isEmpty { return 0 }
        if bits < 40 { return 1 }
        if !PasswordStrength.acceptsMasterPassword(password) { return 2 }
        return bits < 90 ? 3 : 4
    }

    private var tint: Color {
        switch level {
        case 1: .red
        case 2: .orange
        case 3, 4: .green
        default: .secondary
        }
    }

    private var word: String {
        switch level {
        case 1: String(localized: "onboarding.tooWeak")
        case 2: String(localized: "onboarding.almost")
        case 3: String(localized: "onboarding.strong")
        case 4: String(localized: "app.excellent")
        default: String(localized: "onboarding.strength")
        }
    }

    var body: some View {
        HStack(spacing: 10) {
            HStack(spacing: 4) {
                ForEach(0..<4, id: \.self) { index in
                    Capsule()
                        .fill(index < level ? tint : Color.primary.opacity(0.1))
                        .frame(height: 5)
                }
            }
            Text(word)
                .font(.caption.weight(.semibold))
                .foregroundStyle(level == 0 ? Color.secondary : tint)
                .contentTransition(.opacity)
                .frame(minWidth: 70, alignment: .trailing)
        }
        .animation(.spring(duration: 0.35, bounce: 0), value: level)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("onboarding.passwordStrength"))
        .accessibilityValue(Text(word))
        .accessibilityIdentifier("onboarding.strength")
    }
}

/// The rules of the master password: a circle each, turning into a green check once met.
private struct PasswordRulesList: View {
    let rules: [PasswordRule]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(rules) { rule in
                HStack(spacing: 10) {
                    Image(systemName: rule.met ? "checkmark.circle.fill" : "circle")
                        .font(.body.weight(.medium))
                        .foregroundStyle(rule.met ? Color.green : Color.secondary.opacity(0.6))
                        .contentTransition(.symbolEffect(.replace))
                        .frame(width: 22)
                    Text(rule.label)
                        .font(.subheadline)
                        .foregroundStyle(rule.met ? Color.primary : Color.secondary)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text(rule.label))
                .accessibilityValue(Text(rule.met ? String(localized: "onboarding.done") : String(localized: "onboarding.toDo")))
                .accessibilityIdentifier("onboarding.rule.\(rule.id)")
            }
        }
        .padding(.top, 2)
        .animation(.spring(duration: 0.3, bounce: 0.2), value: rules.map(\.met))
    }
}

// MARK: - Secret Key

private struct SecretKeyStep: View {
    @Bindable var model: OnboardingModel
    @State private var saveWarning = false
    #if os(iOS) || os(visionOS)
    @State private var sharedFile: SharedKitFile?
    #endif
    #if os(macOS)
    @State private var cloudDestination: URL?
    @State private var cloudWarning = false
    #endif

    var body: some View {
        if model.path == .create {
            Label("onboarding.vaultCreated", systemImage: "checkmark.seal.fill")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.green)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Color.green.opacity(0.12), in: Capsule())
                .accessibilityIdentifier("onboarding.created")
        }
        StepTitle(
            title: "Range ta Secret Key",
            subtitle: Platform.text(
                mac: "onboarding.itWasCreatedOn",
                phone: "Créée sur cet \(Platform.deviceName), elle ne le quitte jamais. Il te la faudra pour un nouvel appareil si aucun autre n'est à côté."))
        VStack(alignment: .leading, spacing: 8) {
            Text("onboarding.secretKey")
                .font(.system(size: 12, weight: .bold))
                .tracking(0.6)
                .foregroundStyle(.secondary)
            Text(verbatim: model.secretKey ?? "")
                .font(.system(size: 16, design: .monospaced))
                .lineSpacing(5)
                .fixedSize(horizontal: false, vertical: true)
                .privacySensitive()
                .accessibilityIdentifier("onboarding.secretKey")
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .secretKeyCaptureGuard()
        .card()

        Label {
            Text("onboarding.kitPlusMasterPassword")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.shield")
        }
        .font(.subheadline)
        .accessibilityIdentifier("onboarding.kitWarning")
        #if os(macOS)
        .alert(
            "Cet emplacement est synchronisé dans le cloud",
            isPresented: $cloudWarning
        ) {
            Button("app.saveAnyway", role: .destructive) {
                if let url = cloudDestination { model.saveKit(to: url) }
                cloudDestination = nil
            }
            Button("Annuler", role: .cancel) { cloudDestination = nil }
        } message: {
            Text("onboarding.fileWillCopiedTo")
        }
        #endif

        if model.kitData != nil {
            Button {
                model.printKit()
            } label: {
                Label("onboarding.printKit", systemImage: "printer")
                    .font(.system(size: 16, weight: .semibold))
                    .frame(maxWidth: Platform.isMac ? nil : .infinity)
                    .frame(height: Platform.isMac ? 28 : 40)
            }
            .buttonStyle(.glassProminent)
            .controlSize(Platform.isMac ? .large : .regular)
            .accessibilityIdentifier("onboarding.printKit")

            Button("app.saveFile") { saveWarning = true }
                .buttonStyle(.borderless)
                .font(.subheadline)
                .accessibilityIdentifier("onboarding.saveKit")
        }
        KitStoredRow(isOn: $model.kitStoredOffline)
            .accessibilityIdentifier("onboarding.kitStored")
            .onAppear { model.prepareKit() }
            .onDisappear { model.deleteKit() }
            .alert("onboarding.saveEmergencyKitTo", isPresented: $saveWarning) {
                Button("common.continue") { saveFile() }
                Button("Annuler", role: .cancel) {}
            } message: {
                Text(Platform.text(
                    mac: "onboarding.fileCanLeaveDevice",
                    phone: "Un fichier peut quitter cet appareil sans que tu le voies : iCloud Drive, Photos, les messageries et les captures d'écran synchronisent la Secret Key ailleurs. Préfère l'impression, ou enregistre sur un support hors ligne que tu ranges en lieu sûr."))
            }
            #if os(iOS) || os(visionOS)
            .sheet(item: $sharedFile, onDismiss: { model.sharingFinished() }) { file in
                KitShareController(url: file.url) { sharedFile = nil }
                    .ignoresSafeArea()
            }
            #endif
    }

    private func saveFile() {
        #if os(macOS)
        Task {
            guard let url = await KitSavePanel.chooseDestination() else { return }
            if KitDestination.isCloudSynced(url) {
                cloudDestination = url
                cloudWarning = true
            } else {
                model.saveKit(to: url)
            }
        }
        #else
        if let url = model.kitFileForSharing() { sharedFile = SharedKitFile(url: url) }
        #endif
    }
}

/// "Je l'ai rangée hors ligne": a checkbox on Mac; on iPhone and iPad a card whose circle draws a
/// green check, the card turning green with it.
private struct KitStoredRow: View {
    @Binding var isOn: Bool

    var body: some View {
        #if os(macOS)
        CheckRow(title: "Je l'ai rangée hors ligne", isOn: $isOn)
        #else
        Button {
            withAnimation(.spring(duration: 0.4, bounce: 0.25)) { isOn.toggle() }
        } label: {
            HStack(spacing: 14) {
                ZStack {
                    Circle()
                        .strokeBorder(Color.secondary.opacity(isOn ? 0 : 0.45), lineWidth: 1.5)
                    if isOn {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 28))
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, Color.green)
                            .transition(.scale(scale: 0.3).combined(with: .opacity))
                    }
                }
                .frame(width: 28, height: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Je l'ai rangée hors ligne")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text(isOn ? "C'est noté. Garde-la loin de tes écrans." : "Imprimée, ou sur un support hors ligne.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .contentTransition(.opacity)
                }
                Spacer(minLength: 0)
            }
            .padding(16)
            .contentShape(Rectangle())
            .background {
                let shape = RoundedRectangle(cornerRadius: 16, style: .continuous)
                shape.fill(isOn ? AnyShapeStyle(Color.green.opacity(0.10)) : AnyShapeStyle(.fill.tertiary))
                    .overlay(shape.strokeBorder(isOn ? Color.green.opacity(0.6) : .clear, lineWidth: 1.5))
            }
        }
        .onboardingPressable()
        .visionHoverEffect()
        .accessibilityAddTraits(isOn ? .isSelected : [])
        #endif
    }
}

#if os(iOS) || os(visionOS)
private struct SharedKitFile: Identifiable {
    let url: URL
    var id: URL { url }
}
#endif

// MARK: - Biométrie

private struct BiometricsStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        let enabled = model.biometricsEnabled
        VStack(spacing: 18) {
            ZStack {
                RoundedRectangle(cornerRadius: Platform.isMac ? 48 : 32, style: .continuous)
                    .fill(enabled ? AnyShapeStyle(Color.green.opacity(0.12)) : AnyShapeStyle(.fill.tertiary))
                if enabled {
                    CalmCheckmark(size: Platform.isMac ? 64 : 80)
                        .transition(.opacity)
                } else {
                    Image(systemName: OnboardingModel.biometrySymbol)
                        .font(.system(size: Platform.isMac ? 46 : 60, weight: .light))
                        .foregroundStyle(Theme.accent)
                        .symbolEffect(.pulse, options: .repeating, isActive: model.busy)
                        .transition(.opacity)
                }
            }
            .frame(width: Platform.isMac ? 96 : 128, height: Platform.isMac ? 96 : 128)
            .padding(.top, Platform.isMac ? 0 : 28)
            .animation(.smooth(duration: 0.35), value: enabled)
            .accessibilityHidden(true)
            StepTitle(
                title: enabled ? "\(model.biometryName) est activé" : "Déverrouiller avec \(model.biometryName)",
                subtitle: enabled
                    ? "Ton coffre s'ouvre maintenant d'un regard ou d'un doigt."
                    : Platform.text(
                        mac: "onboarding.unlockKeyStaysIn",
                        phone: "La clé reste dans la Secure Enclave. Le mot de passe maître est redemandé tous les 14 jours et si \(model.biometryName) change."),
                centered: !Platform.isMac)
                .contentTransition(.opacity)
                .accessibilityIdentifier(enabled ? "onboarding.biometricsOn" : "onboarding.biometricsOffer")
            if !enabled, !Platform.isMac {
                Text("onboarding.laterCanTurnIt")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity, alignment: Platform.isMac ? .leading : .center)
        #if os(macOS)
        Toggle("onboarding.alsoAllowAppleWatch", isOn: $model.allowWatch)
            .toggleStyle(.checkbox)
            .disabled(enabled)
        #endif
    }
}

// MARK: - Coffres visibles (mode partagé)

private struct VisibleVaultsStep: View {
    let model: OnboardingModel

    var body: some View {
        StepTitle(
            title: "Coffres visibles",
            subtitle: "Sur un appareil partagé, choisis les coffres affichés ici. Les autres restent chiffrés et n'apparaissent pas. Tu pourras changer ce choix dans les réglages.")
        VStack(spacing: 0) {
            ForEach(model.session.allVaults, id: \.id) { vault in
                let hidden = model.session.hiddenVaultIDs.contains(vault.id)
                Toggle(isOn: Binding(
                    get: { !hidden },
                    set: { model.session.setVaultHidden(vault.id, hidden: !$0) }
                )) {
                    HStack(spacing: 12) {
                        VaultBadge(name: vault.meta.name, colorName: vault.meta.color, size: 28)
                        Text(vault.meta.name).font(.body)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                if vault.id != model.session.allVaults.last?.id { Divider().padding(.leading, 56) }
            }
        }
        .card()
    }
}

// MARK: - Restauration

private struct RestoreStep: View {
    @Bindable var model: OnboardingModel
    @State private var scanning = false
    @State private var confirmStartOver = false
    /// Restore only: whether "Créer un nouveau coffre" is offered (asked to iCloud with sync).
    @State private var newVaultOffer: NewVaultOffer?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) { content }
            .task {
                guard model.restoreOnly, newVaultOffer == nil else { return }
                newVaultOffer = await model.newVaultOffer()
            }
    }

    @ViewBuilder private var content: some View {
        StepTitle(
            title: "Utiliser ton Emergency Kit",
            subtitle: Platform.secretKeyText(
                mac: "onboarding.typeSecretKeyPrinted",
                phone: "Scanne le QR code du kit ou tape ta Secret Key. Minuscules, espaces et tirets oubliés sont acceptés."))
        if model.restoreOnly {
            // Only reached when the keychain really lost the Secret Key of the account in the store.
            Label(
                "La Secret Key de ce compte n'est plus dans le trousseau de cet appareil. Saisis-la depuis ton Emergency Kit.",
                systemImage: "key.slash"
            )
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .accessibilityIdentifier("onboarding.secretKeyMissing")
        }
        OnboardingField(
            label: "Secret Key", prompt: "XXXX-XXXX-XXXX-...", text: $model.restoreKey,
            monospaced: true, secretKey: true, identifier: "onboarding.restoreKey")
            .secretKeyCaptureGuard()
        #if os(iOS)
        if SecretKeyScanner.isSupported {
            Button {
                scanning = true
            } label: {
                Label("onboarding.scanKitQrCode", systemImage: "qrcode.viewfinder")
            }
            .buttonStyle(.glass)
            .accessibilityIdentifier("onboarding.scan")
            .sheet(isPresented: $scanning) {
                SecretKeyScannerSheet(accept: model.acceptScannedKit) { key in
                    model.restoreKey = key
                    scanning = false
                }
            }
        }
        #endif
        #if os(macOS)
        if !model.restoreOnly {
            OnboardingField(
                label: "Ton prénom (affiché seulement sur tes appareils)", prompt: "Camille",
                text: $model.displayName, identifier: "onboarding.name")
        }
        #endif
        if model.needsAccountID {
            // Several accounts of this iCloud are not on this device: the kit names which one.
            OnboardingField(
                label: "onboarding.restore.accountID", prompt: "onboarding.restore.accountID.prompt",
                text: $model.restoreAccountID, monospaced: true, identifier: "onboarding.restoreAccountID")
            Text("onboarding.restore.accountID.footer")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        OnboardingField(
            label: "Mot de passe maître", prompt: "Mot de passe maître", text: $model.restorePassword,
            secure: true, identifier: "onboarding.restorePassword")
        if !model.cloudKitEnabled {
            Label(
                "Build local : la synchronisation iCloud est désactivée, seul un compte déjà présent sur cet appareil peut être ouvert.",
                systemImage: "info.circle"
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
        if model.restoreOnly {
            // The account came through the sync: the other device can hand over its Secret Key.
            Button {
                model.choose(.pair)
            } label: {
                Label("onboarding.pairWithMyOther", systemImage: "qrcode")
            }
            .buttonStyle(.glass)
            .accessibilityIdentifier("onboarding.pairInstead")
            switch newVaultOffer {
            case .offered:
                // No Emergency Kit: the local copy cannot be opened, the only way out is a new vault.
                Button {
                    confirmStartOver = true
                } label: {
                    Label("onboarding.createNewVault", systemImage: "plus.circle")
                }
                .buttonStyle(.glass)
                .accessibilityIdentifier("onboarding.startOver")
                .sheet(isPresented: $confirmStartOver) {
                    StartOverConfirmation { try await model.startOver() }
                }
            case .accountInICloud:
                Label(
                    "Ton coffre est dans iCloud : il reviendrait sur cet appareil. Pour l'ouvrir, saisis la Secret Key de ton Emergency Kit.",
                    systemImage: "icloud"
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("onboarding.vaultInICloud")
            case .unavailable:
                Label(
                    "Impossible de vérifier iCloud pour le moment. Vérifie ta connexion puis reviens sur cet écran.",
                    systemImage: "icloud.slash"
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            case nil:
                EmptyView()
            }
        }
    }
}

// MARK: - Terminé

private struct DoneStep: View {
    let model: OnboardingModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var settled = false

    var body: some View {
        CalmCheckmark(size: Platform.isMac ? 64 : 96)
            .frame(maxWidth: .infinity, alignment: Platform.isMac ? .leading : .center)
            .padding(.top, Platform.isMac ? 0 : 44)
            .padding(.bottom, Platform.isMac ? 0 : 4)
            .accessibilityHidden(true)
        VStack(spacing: 8) {
            Text(title)
                .font(Platform.isMac ? .system(size: 30, weight: .bold) : .largeTitle.bold())
                .frame(maxWidth: .infinity, alignment: Platform.isMac ? .leading : .center)
                .accessibilityAddTraits(.isHeader)
                .accessibilityIdentifier("onboarding.doneTitle")
            Text("onboarding.vaultEncryptedAndReady \(Platform.deviceName)")
                .font(Platform.isMac ? .system(size: 15) : .body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(Platform.isMac ? .leading : .center)
                .frame(maxWidth: .infinity, alignment: Platform.isMac ? .leading : .center)
        }
        .opacity(settled ? 1 : 0)
        .offset(y: settled ? 0 : 6)
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                if index > 0 { Divider().padding(.leading, 52) }
                HStack(spacing: 12) {
                    Image(systemName: row.symbol)
                        .font(.body.weight(.medium))
                        .foregroundStyle(Theme.accent)
                        .frame(width: 24)
                        .accessibilityHidden(true)
                    Text(row.label)
                    Spacer()
                    Text(row.value).foregroundStyle(.secondary)
                }
                .font(Platform.isMac ? .system(size: 14) : .body)
                .padding(.horizontal, 16)
                .padding(.vertical, 13)
                .accessibilityElement(children: .combine)
            }
        }
        .card()
        .opacity(settled ? 1 : 0)
        .offset(y: settled ? 0 : 10)
        .onAppear {
            if reduceMotion {
                settled = true
            } else {
                withAnimation(.spring(duration: 0.6, bounce: 0).delay(0.55)) { settled = true }
            }
        }
        #if os(macOS)
        Button("app.openOnepass") { Task { await model.primary() } }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .accessibilityIdentifier("onboarding.primary")
        #endif
    }

    private var title: String {
        let first = model.displayName.split(separator: " ").first.map(String.init) ?? ""
        return Platform.isMac && !first.isEmpty
            ? String(localized: "onboarding.youreAllSet \(first)") : String(localized: "onboarding.youreAllSet")
    }

    private var rows: [(symbol: String, label: String, value: String)] {
        let biometrics: String
        if model.biometricsEnabled {
            biometrics = String(localized: "app.on")
        } else if model.mode == .shared {
            biometrics = String(localized: "onboarding.offSharedDevice")
        } else if !model.biometricsOffered {
            biometrics = String(localized: "onboarding.notAvailable")
        } else {
            biometrics = String(localized: "onboarding.laterInSettings")
        }
        return [
            ("icloud", String(localized: "onboarding.encryptedVaultInIcloud"),
             model.cloudKitEnabled ? String(localized: "app.yes") : String(localized: "onboarding.noLocalBuild")),
            (OnboardingModel.biometrySymbol, model.biometryName, biometrics),
            ("doc.text", "Emergency Kit", model.path == .create ? String(localized: "onboarding.stored") : String(localized: "onboarding.alreadyDone")),
        ]
    }
}

/// A calm success: a ring draws itself, then the check, in green. No bounce, no confetti; drawn at
/// once with Reduce Motion.
struct CalmCheckmark: View {
    let size: CGFloat
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var ring = false
    @State private var check = false

    var body: some View {
        ZStack {
            Circle()
                .fill(Color.green.opacity(0.12))
                .scaleEffect(ring ? 1 : 0.86)
                .opacity(ring ? 1 : 0)
            Circle()
                .trim(from: 0, to: ring ? 1 : 0)
                .stroke(Color.green, style: StrokeStyle(lineWidth: max(size * 0.035, 2.5), lineCap: .round))
                .rotationEffect(.degrees(-90))
                .padding(size * 0.02)
            CheckShape()
                .trim(from: 0, to: check ? 1 : 0)
                .stroke(Color.green, style: StrokeStyle(lineWidth: max(size * 0.07, 4), lineCap: .round, lineJoin: .round))
                .frame(width: size * 0.40, height: size * 0.30)
                .offset(y: size * 0.01)
        }
        .frame(width: size, height: size)
        .onAppear {
            guard !reduceMotion else {
                ring = true
                check = true
                return
            }
            withAnimation(.easeInOut(duration: 0.55).delay(0.1)) { ring = true }
            withAnimation(.easeOut(duration: 0.3).delay(0.5)) { check = true }
        }
    }
}

private struct CheckShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.minX, y: rect.minY + rect.height * 0.55))
        path.addLine(to: CGPoint(x: rect.minX + rect.width * 0.37, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
        return path
    }
}
