import AppIntents

/// Siri and Spotlight phrases, in French.
struct OnePassShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: OpenItemIntent(),
            phrases: ["Ouvrir \(\.$item) dans \(.applicationName)"],
            shortTitle: "Ouvrir un élément",
            systemImageName: "key")
        AppShortcut(
            intent: CopyTotpIntent(),
            phrases: ["Copier le code de \(\.$item) avec \(.applicationName)"],
            shortTitle: "Copier le code",
            systemImageName: "clock.badge.checkmark")
        AppShortcut(
            intent: GeneratePasswordIntent(),
            phrases: ["Générer un mot de passe avec \(.applicationName)"],
            shortTitle: "Générer un mot de passe",
            systemImageName: "dice")
        AppShortcut(
            intent: LockVaultIntent(),
            phrases: ["Verrouiller \(.applicationName)"],
            shortTitle: "Verrouiller OnePass",
            systemImageName: "lock")
    }
}
