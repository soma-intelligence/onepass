import SwiftUI

/// The vault door between the lock screen and the vault (iPhone and iPad).
///
/// Unlock: while Face ID checks, the dial of the lock screen is worked tick by tick (`VaultDial`);
/// once the session opens, it turns a quarter turn further with a mechanical catch, then the lock
/// screen splits at the dial's center: the top panel slides up, the bottom panel slides down, and
/// the vault, already rendered underneath, settles from 96% to full size. About 0.8 s in all.
/// Lock: two plain panels slide in and meet over the screen change, then fade. Reduce Motion: none
/// of this, the plain crossfade of the routes.
///
/// `VaultDoorPassage` is the state machine; the views read it. Every step is started by a real
/// event (the session's state change, an animation's completion), never by a timer.
public struct VaultDoorPassage: Equatable, Sendable {
    public enum Phase: Equatable, Sendable {
        /// Nothing plays.
        case idle
        /// Unlocked: the lock screen stays on top of the vault while its dial turns.
        case turning
        /// The lock screen, split in two pictures, parts over the vault.
        case parting
        /// Locked: two panels slide in and meet over the lock screen.
        case closing
        /// The closed panels fade onto the lock screen.
        case fading
    }

    public enum Event: Equatable, Sendable {
        /// The session went from locked to unlocked.
        case unlocked(reduceMotion: Bool)
        /// The session went from unlocked to locked.
        case locked(reduceMotion: Bool)
        /// The dial finished its turn and the lock screen was captured.
        case turnFinished
        /// The dial finished its turn but the lock screen could not be captured (no window).
        case captureFailed
        /// The opening panels are off screen.
        case panelsOpened
        /// The closing panels have met.
        case panelsClosed
        /// The closed panels have faded.
        case fadeFinished
        /// Anything else that changes the screen under the passage (failure, onboarding, revoked):
        /// the passage stops at once.
        case interrupted
    }

    public private(set) var phase: Phase

    public init(phase: Phase = .idle) { self.phase = phase }

    public mutating func handle(_ event: Event) {
        switch (phase, event) {
        case (_, .interrupted):
            phase = .idle
        case (_, .unlocked(let reduceMotion)):
            phase = reduceMotion ? .idle : .turning
        case (_, .locked(let reduceMotion)):
            phase = reduceMotion ? .idle : .closing
        case (.turning, .turnFinished):
            phase = .parting
        case (.turning, .captureFailed):
            phase = .idle
        case (.parting, .panelsOpened):
            phase = .idle
        case (.closing, .panelsClosed):
            phase = .fading
        case (.fading, .fadeFinished):
            phase = .idle
        default:
            // A late completion of a passage already replaced (lock during an unlock, and so on).
            break
        }
    }

    public var isActive: Bool { phase != .idle }

    /// Alerts raised by the change itself (the Face ID offer after a password unlock) wait until
    /// the door is gone: shown during the passage they sit over the lock screen, call the keyboard
    /// back and ride the parting panels.
    public var holdsPresentations: Bool { isActive }

    /// The lock screen stays mounted above the vault (it is the door until it is captured).
    public var keepsLockOnTop: Bool { phase == .turning }

    /// The vault is rendered underneath while the door is still on screen.
    public var showsVaultUnderneath: Bool { phase == .turning || phase == .parting }

    /// The dial's angle on the lock screen, in degrees.
    public var dialTurn: Double { phase == .turning ? Self.turnDegrees : 0 }

    /// The vault's scale under the door: slightly back while the door is closed, full once open.
    public var vaultScale: CGFloat {
        switch phase {
        case .turning: Self.vaultRestScale
        default: 1
        }
    }

    /// A quarter turn: enough to read as a dial, short enough to feel like a catch.
    public static let turnDegrees: Double = 90
    public static let vaultRestScale: CGFloat = 0.96
}

extension EnvironmentValues {
    /// The angle of the lock screen's dial, driven by the passage.
    @Entry public var vaultDialTurn: Double = 0
}

/// The global y of the lock screen's dial center: the seam where the door splits.
public struct VaultSeamKey: PreferenceKey {
    public static let defaultValue: CGFloat? = nil
    public static func reduce(value: inout CGFloat?, nextValue: () -> CGFloat?) {
        value = nextValue() ?? value
    }
}

#if os(iOS)
import UIKit

/// The lock screen's dial: the Lattice tile as its hub, inside a machined ring of 60 ticks, under a
/// fixed index notch. While Face ID (Touch ID, Optic ID) checks, the dial is worked one tick at a
/// time like a combination (`working`); on success it keeps where it got to and the door's quarter
/// turn (`vaultDialTurn`) carries on from there; a refusal brings it back to zero as it jiggles
/// against its stop. Reduce Motion: it stays still. Reports its center as the door's seam.
public struct VaultDial: View {
    private let size: CGFloat
    private let refusals: Int
    private let working: Bool
    @Environment(\.vaultDialTurn) private var turn
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.displayScale) private var displayScale
    /// How far the check has worked the dial, in ticks.
    @State private var workedTicks = 0

    public init(size: CGFloat, refusals: Int = 0, working: Bool = false) {
        self.size = size
        self.refusals = refusals
        self.working = working
    }

    public var body: some View {
        ZStack {
            ring
            AppGlyph(size: size * 0.5)
        }
        .rotationEffect(.degrees(turn + Self.workAngle(ticks: workedTicks)))
        .modifier(DialJiggle(amount: reduceMotion ? 0 : 7, animatableData: CGFloat(refusals)))
        .task(id: working && !reduceMotion) {
            guard working, !reduceMotion else { return }
            // A first catch at once, so the dial answers the moment the prompt rises.
            while !Task.isCancelled {
                withAnimation(Self.tickAnimation) { workedTicks += 1 }
                try? await Task.sleep(for: Self.tickInterval)
            }
        }
        .onChange(of: refusals) {
            // Back to its stop: the worked ticks unwind as it jiggles.
            withAnimation(.spring(duration: 0.45, bounce: 0)) { workedTicks = 0 }
        }
        .overlay(alignment: .top) { index }
        .frame(width: size, height: size)
        .background {
            GeometryReader { proxy in
                Color.clear.preference(key: VaultSeamKey.self, value: proxy.frame(in: .global).midY)
            }
        }
        .sensoryFeedback(.error, trigger: refusals)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: "OnePass"))
        .accessibilityAddTraits(.isImage)
    }

    /// One tick of the ring per step: 6 degrees.
    public static let tickDegrees: Double = 6
    /// The pace of a worked dial: about the rhythm of the system Face ID glyph's scan.
    public static let tickInterval: Duration = .milliseconds(150)
    /// Each tick lands with a small mechanical catch.
    static let tickAnimation: Animation = .spring(duration: 0.12, bounce: 0.35)

    /// The angle the check has worked the dial to.
    public static func workAngle(ticks: Int) -> Double { Double(ticks) * tickDegrees }

    /// A raised disc with a fine rim, its ticks engraved: real depth from one soft shadow.
    private var ring: some View {
        let hairline = 1 / displayScale
        return ZStack {
            Circle()
                .fill(Color(uiColor: .secondarySystemGroupedBackground))
                .shadow(color: .black.opacity(0.12), radius: size * 0.06, y: size * 0.025)
            Circle()
                .strokeBorder(Color(uiColor: .separator), lineWidth: hairline)
            Ticks()
                .stroke(Color(uiColor: .tertiaryLabel), lineWidth: max(hairline, 1))
                .padding(size * 0.05)
            Circle()
                .strokeBorder(Color(uiColor: .separator), lineWidth: hairline)
                .padding(size * 0.2)
        }
    }

    /// The fixed index above the ring: what the turning ticks are read against.
    private var index: some View {
        Capsule()
            .fill(Theme.accent)
            .frame(width: 3, height: size * 0.07)
            .offset(y: -size * 0.11)
            .accessibilityHidden(true)
    }

    /// 60 ticks on the rim, every fifth one longer.
    private struct Ticks: Shape {
        func path(in rect: CGRect) -> Path {
            let center = CGPoint(x: rect.midX, y: rect.midY)
            let radius = min(rect.width, rect.height) / 2
            var path = Path()
            for tick in 0 ..< 60 {
                let angle = Double(tick) / 60 * 2 * .pi
                let length = radius * (tick % 5 == 0 ? 0.14 : 0.07)
                let direction = CGPoint(x: sin(angle), y: -cos(angle))
                path.move(to: CGPoint(x: center.x + direction.x * radius, y: center.y + direction.y * radius))
                path.addLine(to: CGPoint(x: center.x + direction.x * (radius - length),
                                         y: center.y + direction.y * (radius - length)))
            }
            return path
        }
    }
}

/// A short rotational jiggle that dies out: the dial tried to turn and met its stop.
private struct DialJiggle: GeometryEffect {
    var amount: CGFloat
    var animatableData: CGFloat

    func effectValue(size: CGSize) -> ProjectionTransform {
        let progress = animatableData - animatableData.rounded(.down)
        let degrees = amount * sin(progress * .pi * 6) * (1 - progress)
        let radians = degrees * .pi / 180
        let center = CGAffineTransform(translationX: size.width / 2, y: size.height / 2)
        let transform = CGAffineTransform(translationX: -size.width / 2, y: -size.height / 2)
            .concatenating(CGAffineTransform(rotationAngle: radians))
            .concatenating(center)
        return ProjectionTransform(transform)
    }
}

/// The opening door: the captured lock screen in two pictures, split at `seam`, sliding apart with a
/// hairline and a soft shadow on each seam edge. Touches pass to the vault underneath.
public struct VaultDoorPanels: View {
    private let snapshot: UIImage
    private let seam: CGFloat
    private let parted: CGFloat
    @Environment(\.displayScale) private var displayScale

    /// `parted`: 0 closed at the seam, 1 both panels off screen.
    public init(snapshot: UIImage, seam: CGFloat, parted: CGFloat) {
        self.snapshot = snapshot
        self.seam = seam
        self.parted = parted
    }

    public var body: some View {
        GeometryReader { proxy in
            let height = proxy.size.height
            let seam = min(max(self.seam, 0), height)
            // Past the edge by the shadow's reach, so no shadow lingers at the screen's border.
            let reach: CGFloat = 32
            ZStack(alignment: .top) {
                panel(top: true, height: seam, size: proxy.size)
                    .offset(y: -parted * (seam + reach))
                panel(top: false, height: height - seam, size: proxy.size)
                    .offset(y: parted * (height - seam + reach))
            }
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private func panel(top: Bool, height: CGFloat, size: CGSize) -> some View {
        Image(uiImage: snapshot)
            .resizable()
            .frame(width: size.width, height: size.height)
            .frame(width: size.width, height: height, alignment: top ? .top : .bottom)
            .clipped()
            .overlay(alignment: top ? .bottom : .top) {
                Rectangle()
                    .fill(Color(uiColor: .separator))
                    .frame(height: 1 / displayScale)
            }
            .compositingGroup()
            .shadow(color: .black.opacity(0.18 * parted.clampedUnit.risingEdge), radius: 14,
                    y: top ? 4 : -4)
            .frame(height: size.height, alignment: top ? .top : .bottom)
    }
}

/// The closing door: two panels in the lock screen's background meet at the middle, then fade.
public struct VaultDoorClosing: View {
    private let parted: CGFloat
    private let opacity: Double
    @Environment(\.displayScale) private var displayScale

    public init(parted: CGFloat, opacity: Double) {
        self.parted = parted
        self.opacity = opacity
    }

    public var body: some View {
        GeometryReader { proxy in
            let travel = proxy.size.height / 2 + 32
            VStack(spacing: 0) {
                half(top: true).offset(y: -parted * travel)
                half(top: false).offset(y: parted * travel)
            }
        }
        .ignoresSafeArea()
        .opacity(opacity)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private func half(top: Bool) -> some View {
        Color(uiColor: .systemGroupedBackground)
            .overlay(alignment: top ? .bottom : .top) {
                Rectangle()
                    .fill(Color(uiColor: .separator))
                    .frame(height: 1 / displayScale)
            }
            .shadow(color: .black.opacity(0.14), radius: 12, y: top ? 4 : -4)
            .zIndex(top ? 1 : 0)
    }
}

private extension CGFloat {
    var clampedUnit: CGFloat { Swift.min(Swift.max(self, 0), 1) }
    /// The shadow shows as soon as the panels leave the seam, at full strength by 15%.
    var risingEdge: CGFloat { Swift.min(self / 0.15, 1) }
}

#Preview("VaultDial") {
    VStack(spacing: 40) {
        VaultDial(size: 120)
        VaultDial(size: 120).environment(\.vaultDialTurn, 90)
        VaultDial(size: 120, working: true)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(Color(uiColor: .systemGroupedBackground))
}
#endif
