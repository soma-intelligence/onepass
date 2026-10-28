import DesignKit
import SwiftUI
import VaultKit

/// The body of the current step, shared by the iPhone, iPad and Mac layouts.
struct OnboardingStepContent: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
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
            if let busy = model.busyMessage {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(busy).foregroundStyle(.secondary)
                }
                .font(.subheadline)
            }
            if let error = model.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.subheadline)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("onboarding.error")
                if model.offerRestore {
                    Button("J'ai mon Emergency Kit") { model.switchToRestore() }
                        .buttonStyle(.glass)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .disabled(model.busy)
    }
}

// MARK: - Shared pieces

struct StepTitle: View {
    let title: LocalizedStringResource
    let subtitle: LocalizedStringResource?
    var centered = false

    var body: some View {
        VStack(alignment: centered ? .center : .leading, spacing: 10) {
            Text(title)
                .font(Platform.isMac ? .system(size: 28, weight: .bold) : .system(size: 30, weight: .bold))
                .multilineTextAlignment(centered ? .center : .leading)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            if let subtitle {
                Text(subtitle)
                    .font(Platform.isMac ? .system(size: 15) : .system(size: 16))
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
                    shape.fill(.fill.tertiary)
                        .overlay(shape.strokeBorder(selected ? Theme.accent : .clear, lineWidth: 2))
                }
            }
    }
}

extension View {
    func card(selected: Bool = false) -> some View { modifier(CardBackground(selected: selected)) }
}

/// Text or secure field in the mockup style (filled on iPhone, bordered on Mac).
struct OnboardingField: View {
    let label: LocalizedStringResource
    let prompt: LocalizedStringResource
    @Binding var text: String
    var secure = false
    var mismatch = false
    var monospaced = false
    /// Secret Key entry: no autocorrection, ASCII keyboard, capitals, hidden from screen captures.
    var secretKey = false
    var identifier: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.subheadline).foregroundStyle(.secondary)
            Group {
                if secure {
                    SecureField(text: $text, prompt: Text(prompt)) { Text(label) }
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
            .padding(.horizontal, 14)
            .frame(height: Platform.isMac ? 40 : 52)
            .background {
                let shape = RoundedRectangle(cornerRadius: Platform.isMac ? 10 : 14, style: .continuous)
                if Platform.isMac {
                    shape.fill(.background)
                        .overlay(shape.strokeBorder(mismatch ? Color.red : Color.primary.opacity(0.15),
                                                    lineWidth: mismatch ? 2 : 1))
                } else {
                    shape.fill(.fill.tertiary)
                        .overlay(shape.strokeBorder(mismatch ? Color.red : .clear, lineWidth: 2))
                }
            }
            .accessibilityIdentifier(identifier)
        }
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
            AppGlyph(size: 88).padding(.top, 30)
        }
        Text("Bienvenue dans OnePass")
            .font(.system(size: Platform.isMac ? 32 : 34, weight: .bold))
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityAddTraits(.isHeader)
        Text(subtitle)
            .font(Platform.isMac ? .system(size: 15) : .system(size: 17))
            .foregroundStyle(.secondary)
            .lineSpacing(2)
            .fixedSize(horizontal: false, vertical: true)
        VStack(spacing: 10) {
            choice(
                "Créer un coffre", "Première fois sur OnePass", symbol: "plus", prominent: true,
                identifier: "onboarding.create"
            ) { model.choose(.create) }
            choice(
                "J'ai mon Emergency Kit", "Aucun autre appareil sous la main", symbol: "doc.text",
                identifier: "onboarding.restore"
            ) { model.choose(.restore) }
            choice(
                "J'ai déjà OnePass sur un autre appareil", "Connexion par QR code", symbol: "qrcode",
                identifier: "onboarding.pair"
            ) { model.choose(.pair) }
        }
        .padding(.top, 8)
    }

    private var subtitle: LocalizedStringResource {
        if Platform.isMac {
            "Tous tes mots de passe, passkeys, cartes et documents, chiffrés avec une cryptographie qui résiste aux ordinateurs quantiques."
        } else {
            "Mots de passe, passkeys, cartes et documents, chiffrés sur ton \(Platform.deviceName) avec une crypto qui résiste aux ordinateurs quantiques."
        }
    }

    private func choice(
        _ title: LocalizedStringResource, _ subtitle: LocalizedStringResource, symbol: String,
        prominent: Bool = false, soon: Bool = false,
        identifier: String, action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                RoundedRectangle(cornerRadius: 11, style: .continuous)
                    .fill(prominent ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.fill.secondary))
                    .frame(width: 40, height: 40)
                    .overlay {
                        Image(systemName: symbol)
                            .font(.system(size: 17, weight: .semibold))
                            .foregroundStyle(prominent ? Color.white : Color.primary)
                    }
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.system(size: Platform.isMac ? 15 : 16, weight: .semibold))
                    Text(subtitle).font(.system(size: 13.5)).foregroundStyle(.secondary)
                }
                .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
                if soon {
                    Text("Bientôt")
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(.fill.secondary, in: Capsule())
                } else if Platform.isMac {
                    Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.secondary)
                }
            }
            .padding(Platform.isMac ? 16 : 14)
            .contentShape(Rectangle())
            .card()
        }
        .buttonStyle(.plain)
        .visionHoverEffect()
        .disabled(soon)
        .opacity(soon ? 0.55 : 1)
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
    }

    private func option(
        _ mode: DeviceMode, _ title: LocalizedStringResource, _ subtitle: LocalizedStringResource
    ) -> some View {
        let selected = model.mode == mode
        return Button {
            model.mode = mode
        } label: {
            HStack(spacing: 14) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.system(size: 16, weight: .semibold))
                    Text(subtitle).font(.system(size: 13.5)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .font(.title3)
                    .foregroundStyle(selected ? Theme.accent : .secondary)
            }
            .padding(16)
            .contentShape(Rectangle())
            .card(selected: selected)
        }
        .buttonStyle(.plain)
        .visionHoverEffect()
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier(mode == .personal ? "onboarding.personal" : "onboarding.shared")
    }
}

// MARK: - Mot de passe maître

private struct PasswordStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        StepTitle(
            title: Platform.isMac ? "Choisis ton mot de passe maître" : "Ton mot de passe maître",
            subtitle: Platform.text(
                mac: "C'est le seul mot de passe à retenir. Personne ne peut le récupérer pour toi, pas même nous.",
                phone: "Le seul à retenir. Personne ne peut le récupérer pour toi."))
        #if os(macOS)
        OnboardingField(
            label: "Ton prénom (affiché seulement sur tes appareils)", prompt: "Camille",
            text: $model.displayName, identifier: "onboarding.name")
        #endif
        OnboardingField(
            label: "Mot de passe maître",
            prompt: Platform.isMac ? "Cinq mots tirés au hasard marchent bien" : "Cinq mots tirés au hasard",
            text: $model.password, secure: true, identifier: "onboarding.password")
        StrengthMeter(bits: model.passwordBits)
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Button {
                model.generateMasterPassword()
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
        OnboardingField(
            label: "Confirme-le", prompt: "", text: $model.confirmation, secure: true,
            mismatch: model.confirmationMismatch, identifier: "onboarding.confirm")
        if model.confirmationMismatch {
            Text("Les deux saisies sont différentes.").font(.footnote).foregroundStyle(.red)
        }
        if Platform.isMac {
            Label {
                Text("Conseil : cinq mots tirés au hasard (« tapis-orage-girafe-violon-nuage ») sont plus solides et plus faciles à retenir qu'un mot compliqué. « Générer » en tire cinq pour toi.")
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
        StepTitle(
            title: "Range ta Secret Key",
            subtitle: Platform.text(
                mac: "Elle a été créée sur ce Mac et ne le quitte jamais. Avec ton mot de passe maître, elle protège ton coffre même si iCloud était piraté. Il te la faudra pour un nouvel appareil sans autre appareil à côté.",
                phone: "Créée sur cet \(Platform.deviceName), elle ne le quitte jamais. Il te la faudra pour un nouvel appareil si aucun autre n'est à côté."))
        VStack(alignment: .leading, spacing: 8) {
            Text("SECRET KEY")
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
            Text("Ce kit plus ton mot de passe maître donnent un accès complet à ton coffre. Imprime-le et range la feuille hors ligne ; ne le photographie pas.")
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
            Button("Enregistrer quand même", role: .destructive) {
                if let url = cloudDestination { model.saveKit(to: url) }
                cloudDestination = nil
            }
            Button("Annuler", role: .cancel) { cloudDestination = nil }
        } message: {
            Text("Le fichier sera copié sur les serveurs de ce service et sur tes autres appareils. Avec ton mot de passe maître, il donne un accès complet à ton coffre.")
        }
        #endif

        if model.kitData != nil {
            Button {
                model.printKit()
            } label: {
                Label("Imprimer le kit", systemImage: "printer")
                    .font(.system(size: 16, weight: .semibold))
                    .frame(maxWidth: Platform.isMac ? nil : .infinity)
                    .frame(height: Platform.isMac ? 28 : 40)
            }
            .buttonStyle(.glassProminent)
            .controlSize(Platform.isMac ? .large : .regular)
            .accessibilityIdentifier("onboarding.printKit")

            Button("Enregistrer un fichier…") { saveWarning = true }
                .buttonStyle(.borderless)
                .font(.subheadline)
                .accessibilityIdentifier("onboarding.saveKit")
        }
        CheckRow(title: "Je l'ai rangée hors ligne", isOn: $model.kitStoredOffline)
            .accessibilityIdentifier("onboarding.kitStored")
            .onAppear { model.prepareKit() }
            .onDisappear { model.deleteKit() }
            .alert("Enregistrer l'Emergency Kit dans un fichier ?", isPresented: $saveWarning) {
                Button("Continuer") { saveFile() }
                Button("Annuler", role: .cancel) {}
            } message: {
                Text(Platform.text(
                    mac: "Un fichier peut quitter cet appareil sans que tu le voies : iCloud Drive, Photos, les messageries et les captures d'écran synchronisent la Secret Key ailleurs. Préfère l'impression, ou enregistre sur une clé USB que tu ranges hors ligne.",
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
        VStack(spacing: 18) {
            RoundedRectangle(cornerRadius: Platform.isMac ? 48 : 30, style: .continuous)
                .fill(.fill.tertiary)
                .frame(width: Platform.isMac ? 96 : 120, height: Platform.isMac ? 96 : 120)
                .overlay {
                    Image(systemName: OnboardingModel.biometrySymbol)
                        .font(.system(size: Platform.isMac ? 46 : 60, weight: .light))
                        .foregroundStyle(Theme.accent)
                }
                .padding(.top, Platform.isMac ? 0 : 30)
                .accessibilityHidden(true)
            StepTitle(
                title: "Déverrouiller avec \(model.biometryName)",
                subtitle: Platform.text(
                mac: "La clé de déverrouillage reste dans la Secure Enclave de ce Mac. Ajouter une empreinte l'invalide : le mot de passe maître est alors redemandé. Il est aussi redemandé tous les 14 jours.",
                phone: "La clé reste dans la Secure Enclave. Le mot de passe maître est redemandé tous les 14 jours et si \(model.biometryName) change."),
                centered: !Platform.isMac)
        }
        .frame(maxWidth: .infinity, alignment: Platform.isMac ? .leading : .center)
        #if os(macOS)
        Toggle("Accepter aussi l'Apple Watch", isOn: $model.allowWatch)
            .toggleStyle(.checkbox)
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
                mac: "Tape la Secret Key imprimée sur ton kit. Minuscules, espaces et tirets oubliés sont acceptés.",
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
                Label("Scanner le QR code du kit", systemImage: "qrcode.viewfinder")
            }
            .buttonStyle(.glass)
            .accessibilityIdentifier("onboarding.scan")
            .sheet(isPresented: $scanning) {
                SecretKeyScannerSheet { key in
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
            switch newVaultOffer {
            case .offered:
                // No Emergency Kit: the local copy cannot be opened, the only way out is a new vault.
                Button {
                    confirmStartOver = true
                } label: {
                    Label("Créer un nouveau coffre", systemImage: "plus.circle")
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

    var body: some View {
        Circle()
            .fill(Color.green.opacity(0.2))
            .frame(width: Platform.isMac ? 64 : 90, height: Platform.isMac ? 64 : 90)
            .overlay {
                Image(systemName: "checkmark")
                    .font(.system(size: Platform.isMac ? 28 : 40, weight: .bold))
                    .foregroundStyle(.green)
            }
            .frame(maxWidth: .infinity, alignment: Platform.isMac ? .leading : .center)
            .padding(.top, Platform.isMac ? 0 : 40)
            .accessibilityHidden(true)
        Text(title)
            .font(.system(size: Platform.isMac ? 30 : 32, weight: .bold))
            .frame(maxWidth: .infinity, alignment: Platform.isMac ? .leading : .center)
            .accessibilityAddTraits(.isHeader)
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                if index > 0 { Divider().padding(.leading, 16) }
                HStack {
                    Text(row.label)
                    Spacer()
                    Text(row.value).foregroundStyle(.secondary)
                }
                .font(Platform.isMac ? .system(size: 14) : .body)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
        }
        .card()
        #if os(macOS)
        Button("Ouvrir OnePass") { Task { await model.primary() } }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .accessibilityIdentifier("onboarding.primary")
        #endif
    }

    private var title: String {
        let first = model.displayName.split(separator: " ").first.map(String.init) ?? ""
        return Platform.isMac && !first.isEmpty
            ? String(localized: "Tout est prêt, \(first)") : String(localized: "Tout est prêt")
    }

    private var rows: [(label: String, value: String)] {
        let biometrics: String
        if model.biometricsEnabled {
            biometrics = String(localized: "Activé")
        } else if model.mode == .shared {
            biometrics = String(localized: "Désactivé (appareil partagé)")
        } else if !model.biometricsOffered {
            biometrics = String(localized: "Non disponible")
        } else {
            biometrics = String(localized: "Plus tard")
        }
        return [
            (String(localized: "Coffre chiffré dans iCloud"),
             model.cloudKitEnabled ? String(localized: "Oui") : String(localized: "Non (build local)")),
            (model.biometryName, biometrics),
            ("Emergency Kit", model.path == .create ? String(localized: "Rangé") : String(localized: "Déjà fait")),
        ]
    }
}
