import DesignKit
import SwiftUI
import VaultKit

/// First question of "J'ai déjà OnePass sur un autre appareil" (spec 2b section 6): personal, shared
/// or public. Public is a guest session: a few items lent for a while, nothing kept here.
struct PairingModeStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        StepTitle(
            title: "Comment vas-tu utiliser cet appareil ?",
            subtitle: "Ton autre appareil le valide en scannant un QR code. Rien ne passe par un serveur.")
        VStack(spacing: 10) {
            option(
                .personal, "Personnel", "Il est à toi : tout ton coffre, déverrouillage par \(model.biometryName).",
                symbol: "person")
            option(
                .shared, "Partagé", "Famille ou bureau : ton coffre, sans \(model.biometryName), coffres visibles au choix.",
                symbol: "person.2")
            option(
                .public, "Public", "L'appareil de quelqu'un d'autre : quelques éléments prêtés, en lecture seule, rien n'y reste.",
                symbol: "person.badge.clock")
        }
    }

    private func option(
        _ mode: FfiDeviceMode, _ title: LocalizedStringResource, _ subtitle: LocalizedStringResource, symbol: String
    ) -> some View {
        let selected = model.pairDeviceMode == mode
        return Button {
            model.pairDeviceMode = mode
        } label: {
            HStack(spacing: 14) {
                RoundedRectangle(cornerRadius: 11, style: .continuous)
                    .fill(selected ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.fill.secondary))
                    .frame(width: 40, height: 40)
                    .overlay {
                        Image(systemName: symbol)
                            .font(.system(size: 16, weight: .semibold))
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
        .accessibilityIdentifier("pairing.mode.\(DeviceKindText.modeKey(mode))")
    }
}

/// Names and symbols of device kinds and modes, shared by the pairing screens and Réglages > Appareils.
enum DeviceKindText {
    static func symbol(_ kind: FfiDeviceKind) -> String {
        switch kind {
        case .phone: "iphone"
        case .tablet: "ipad"
        case .mac: "laptopcomputer"
        case .vision: "visionpro"
        case .other: "desktopcomputer"
        }
    }

    static func kind(_ kind: FfiDeviceKind) -> String {
        switch kind {
        case .phone: "iPhone"
        case .tablet: "iPad"
        case .mac: "Mac"
        case .vision: "Apple Vision Pro"
        case .other: String(localized: "Autre appareil")
        }
    }

    static func mode(_ mode: FfiDeviceMode) -> String {
        switch mode {
        case .personal: String(localized: "Personnel")
        case .shared: String(localized: "Partagé")
        case .public: String(localized: "Public")
        }
    }

    static func modeKey(_ mode: FfiDeviceMode) -> String {
        switch mode {
        case .personal: "personal"
        case .shared: "shared"
        case .public: "public"
        }
    }
}
