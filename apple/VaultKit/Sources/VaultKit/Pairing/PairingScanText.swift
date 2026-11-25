import Foundation

/// What a QR code scanned by a new device asks for. The unlocked device shows one of two codes: an
/// invite (`OPPAIR1:`, Réglages > Appareils > Ajouter) or a rendezvous code (`OPPAIR2:`, Fichier >
/// Configurer un appareil… on the Mac). The new device's scanner takes both.
public enum PairingScanText: Equatable, Sendable {
    /// `OPPAIR2:...`: the new device joins with `PairingNewcomerFlow.join(code:connector:)`.
    case rendezvous(String)
    /// `OPPAIR1:...`: the new device joins the invite (`PairingNewcomerFlow(invite:)`).
    case invite(String)

    public static let rendezvousPrefix = "OPPAIR2:"
    public static let invitePrefix = "OPPAIR1:"

    /// The scanned text sorted, trimmed; nil when it is not a OnePass pairing code (no URL is ever
    /// accepted, so the system camera never opens one).
    public static func route(_ scanned: String) -> PairingScanText? {
        let text = scanned.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix(rendezvousPrefix), text.count > rendezvousPrefix.count { return .rendezvous(text) }
        if text.hasPrefix(invitePrefix), text.count > invitePrefix.count { return .invite(text) }
        return nil
    }
}
