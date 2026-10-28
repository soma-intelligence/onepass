import DesignKit
import SwiftUI
import VaultKit

/// The account arrived (personal or shared): the master password opens it. A wrong password keeps
/// the grant for another try (ruling A9); leaving the screen means pairing again.
struct PairingPasswordStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        StepTitle(
            title: "Saisis ton mot de passe maître",
            subtitle: "Ton compte est arrivé sur cet appareil. Ton mot de passe maître l'ouvre, comme sur tes autres appareils.")
        OnboardingField(
            label: "Mot de passe maître", prompt: "Mot de passe maître", text: $model.restorePassword,
            secure: true, identifier: "pairing.password")
            .onSubmit { Task { await model.primary() } }
        Label(
            "Ne quitte pas cet écran : sans ton mot de passe, il faudra refaire l'appairage.",
            systemImage: "info.circle")
            .font(.footnote)
            .foregroundStyle(.secondary)
    }
}
