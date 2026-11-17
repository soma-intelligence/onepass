#if os(iOS)
import DesignKit
import SwiftUI

// The pieces of the RX lock screen (iPhone and iPad, `RXDesign` on): its art, its backdrop, the
// breathing halo around the account while Face ID checks, and the zoom-through that carries the
// lock screen into the vault (`RootView`). The classic look keeps the vault dial and door.

private typealias RX = Theme.RX

/// The art behind the RX lock screen.
enum RXLockArt {
    /// The picture and whether it is light (dark words over it): the one place the lock screen
    /// picks its art.
    @MainActor static func lockArt(colorScheme: ColorScheme) -> (image: Image, isLight: Bool) {
        // The wallpaper chosen for Accueil (Réglages > Général > Fond d'écran), so locking and
        // unlocking stay on the same picture.
        let stored = AppModel.browseDefaults.string(forKey: RXWallpaper.storageKey) ?? RXWallpaper.automatic
        let wallpaper = RXWallpaper.resolve(stored, colorScheme: colorScheme)
        return (wallpaper.image, wallpaper.isLight)
    }
}

/// The art full bleed under the whole screen, with the veil of `RXHeroPage`'s backdrop: white over
/// a light picture, black over a dark one, stronger under Reduce Transparency or Increase Contrast.
struct RXLockBackdrop: View {
    let image: Image
    let isLight: Bool
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    var body: some View {
        let flat = Theme.Wash.isFlat(increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency)
        let veil: Color = isLight ? .white : .black
        let stops = isLight ? RX.Veil.lightHero(flat: flat) : RX.Veil.hero(flat: flat)
        ZStack {
            RX.Wash.artPlaceholder
            image
                .resizable()
                .scaledToFill()
            LinearGradient(
                stops: [
                    .init(color: veil.opacity(stops[0]), location: 0),
                    .init(color: veil.opacity(stops[1]), location: 0.55),
                    .init(color: veil.opacity(stops[2]), location: 1),
                ],
                startPoint: .top, endPoint: .bottom)
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

/// The halo around the account avatar while Face ID (Touch ID, Optic ID) checks: a soft glow and
/// a thin ring that breathe in and out, calm and slow. Reduce Motion: the ring stays still. It
/// fades in and out with the check.
struct RXLockHalo: ViewModifier {
    let checking: Bool
    let diameter: CGFloat
    /// The art is light: an accent ring (a white one would vanish on it).
    let onLight: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// How far the ring sits outside the avatar.
    private var inset: CGFloat { RX.Space.s }

    func body(content: Content) -> some View {
        content
            .background {
                if checking {
                    halo
                        .transition(.opacity)
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)
                }
            }
            .animation(.smooth, value: checking)
    }

    private var tint: Color { onLight ? RX.Palette.accent.color : .white }

    @ViewBuilder private var halo: some View {
        let ring = Circle()
            .strokeBorder(tint.opacity(Self.ringOpacity), lineWidth: Self.ringWidth)
            .frame(width: diameter + 2 * inset, height: diameter + 2 * inset)
        let glow = Circle()
            .fill(tint.opacity(Self.glowOpacity))
            .frame(width: diameter + 2 * inset, height: diameter + 2 * inset)
            .blur(radius: RX.Space.l)
        if reduceMotion {
            ZStack { glow; ring }
        } else {
            ZStack { glow; ring }
                .phaseAnimator([false, true]) { halo, breathedIn in
                    halo
                        .scaleEffect(breathedIn ? Self.breathScale : 1)
                        .opacity(breathedIn ? 1 : Self.restOpacity)
                } animation: { _ in
                    .easeInOut(duration: Self.breath)
                }
        }
    }

    /// One breath in (or out), in seconds: slow enough to read as waiting, not as an alarm.
    static let breath: TimeInterval = 1.1
    static let breathScale: CGFloat = 1.12
    static let restOpacity: Double = 0.55
    static let ringOpacity: Double = 0.7
    static let ringWidth: CGFloat = 2
    static let glowOpacity: Double = 0.35
}

/// The zoom-through between the RX lock screen and the vault: the lock screen grows a little, blurs
/// and fades as the vault settles from just behind it to full size. Locking plays it backwards.
enum RXLockPassage {
    /// The whole passage (`.smooth`, 0.45 s).
    static let animation: Animation = .smooth(duration: 0.45)
    /// How much the lock screen grows as it leaves.
    static let throughScale: CGFloat = 1.08
    /// How soft the lock screen gets as it leaves.
    static let throughBlur: CGFloat = RX.Space.m
}

/// The lock screen's side of the passage: `progress` 0 on screen, 1 gone through.
struct RXZoomThrough: ViewModifier {
    let progress: CGFloat

    func body(content: Content) -> some View {
        content
            .scaleEffect(1 + (RXLockPassage.throughScale - 1) * progress)
            .blur(radius: RXLockPassage.throughBlur * progress)
            .opacity(1 - progress)
    }
}

extension AnyTransition {
    /// The RX lock screen, leaving into the vault or coming back over it.
    static var rxLockZoomThrough: AnyTransition {
        .modifier(active: RXZoomThrough(progress: 1), identity: RXZoomThrough(progress: 0))
    }

    /// The vault under the RX lock screen: from just behind it (the door's rest scale) to full size.
    static var rxVaultArrival: AnyTransition {
        .opacity.combined(with: .scale(scale: VaultDoorPassage.vaultRestScale))
    }
}
#endif
