import DesignKit
import SwiftUI

extension View {
    /// Pull to refresh. On iPhone and iPad the system spinner gives way to a vault combination dial
    /// (`VaultDialRefresh`); elsewhere, and with VoiceOver on, it is the system `refreshable`.
    func vaultRefresh(_ action: @escaping @MainActor () async -> Void) -> some View {
        #if os(iOS)
        modifier(VaultDialRefresh(action: action))
        #else
        refreshable { await action() }
        #endif
    }
}

#if os(iOS)

/// Where a pull to refresh stands.
enum VaultDialPhase: Equatable {
    /// The list is pulled down: `progress` runs 0 to 1, 1 at the release threshold.
    case pulling(progress: CGFloat)
    /// Released past the threshold: the screen reloads while the dial dials a combination.
    case refreshing(since: Date)
    /// The reload is over: the wheel goes back to 0, turns a last quarter to open, the drawing leaves.
    /// `refreshed` is when the reload began, so the dial carries on from where it was.
    case finishing(since: Date, refreshed: Date)
}

/// The app's pull to refresh: pulling turns a vault dial, one soft click every ten graduations;
/// the reload holds `VaultDialHeader.height` open above the first row while the dial dials a
/// combination (right, left, right); when it is done the wheel comes back to 0, throws
/// the bolts with a last quarter turn while the keyhole lights up, and the list springs back up.
///
/// The system `refreshable` still runs it, its spinner made invisible: it keeps the gesture's
/// priority over a sheet's swipe to dismiss (Réglages is a sheet) and decides when the reload starts.
struct VaultDialRefresh: ViewModifier {
    var action: @MainActor () async -> Void

    /// The pull at which the dial has made its full turn: where the system starts the reload
    /// (160 to 175 pt on iOS 26).
    static let threshold: CGFloat = 160

    /// What the system refresh control holds open on its own while it runs (measured on iOS 26);
    /// the modifier adds the rest so the dial gets its full height.
    static let systemGap: CGFloat = 48

    /// The system spinner stays, invisible, under the dial.
    private static let hideSpinner: Void = { UIRefreshControl.appearance().tintColor = .clear }()

    init(action: @escaping @MainActor () async -> Void) {
        self.action = action
        _ = Self.hideSpinner
    }
    /// The least time the dial stays, so a fast reload still shows a full turn of the combination.
    static let minimum: Duration = .milliseconds(1500)

    @Environment(\.accessibilityVoiceOverEnabled) private var voiceOver
    @State private var pull: CGFloat = 0
    @State private var inset: CGFloat = 0
    @State private var gap: CGFloat = 0
    @State private var hold: CGFloat = 0
    @State private var phase: VaultDialPhase = .pulling(progress: 0)
    @State private var busy = false
    /// Brought back to the top as the held gap closes, or the list would stay scrolled by the gap.
    @State private var position = ScrollPosition(edge: .top)

    private var armed: Bool { !busy && pull >= Self.threshold }
    /// One click for every ten graduations the dial passes while pulled.
    private var notch: Int {
        guard case .pulling(let k) = phase else { return -1 }
        return Int(VaultDialHeader.pullAngle(k) / 36)
    }

    func body(content: Content) -> some View {
        if voiceOver {
            content.refreshable { await action() }
        } else {
            content
                .safeAreaPadding(.top, hold)
                .scrollPosition($position)
                .onScrollGeometryChange(for: [CGFloat].self) { geo in
                    [geo.contentOffset.y, geo.contentInsets.top]
                } action: { _, now in
                    // The bars end at `inset` (the held gap left out); the first row starts at
                    // -offset. The gap between them is what the drawing fills.
                    inset = now[1] - hold
                    gap = max(0, -now[0] - inset)
                    pull = max(0, -(now[0] + now[1]))
                    if !busy { phase = .pulling(progress: min(1.25, pull / Self.threshold)) }
                }
                .refreshable { await run() }
                .overlay(alignment: .top) {
                    if pull > 0 || hold > 0 {
                        // The drawing rides on the first row (its top cut off while the gap is
                        // short), centred once it fits.
                        let h = VaultDialHeader.height
                        Color.clear
                            .frame(maxWidth: .infinity)
                            .frame(height: gap)
                            .overlay(alignment: .bottom) {
                                VaultDialHeader(phase: phase)
                                    .frame(height: h)
                                    .offset(y: gap > h ? -(gap - h) / 2 : 0)
                            }
                            .clipped()
                            .padding(.top, inset)
                            .ignoresSafeArea(edges: .top)
                            .allowsHitTesting(false)
                    }
                }
                .sensoryFeedback(.selection, trigger: notch) { old, new in old >= 0 && new > old }
                .sensoryFeedback(.impact(weight: .medium), trigger: armed) { _, now in now }
        }
    }

    private func run() async {
        busy = true
        let began = Date()
        phase = .refreshing(since: began)
        // Held at once, the way the system's refresh control holds its gap: the list is already
        // pulled past it and settles onto it on its own. The search field folds away as it settles,
        // which would scroll the gap under the bars, so the list goes to its top too.
        hold = VaultDialHeader.height - Self.systemGap
        withAnimation(.spring(duration: 0.35, bounce: 0)) { position.scrollTo(edge: .top) }
        let clock = ContinuousClock(), t0 = clock.now
        await action()
        let left = Self.minimum - (clock.now - t0)
        if left > .zero { try? await Task.sleep(for: left) }
        phase = .finishing(since: Date(), refreshed: began)
        try? await Task.sleep(for: VaultDialHeader.finish)
        withAnimation(.spring(duration: 0.45, bounce: 0)) {
            hold = 0
            position.scrollTo(edge: .top)
        }
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(450))
            phase = .pulling(progress: 0)
            busy = false
        }
    }
}

/// The band above a pulled list: a brushed gunmetal combination dial in a steel bezel, the red index
/// at 12 o'clock, and a three-spoke vault handle to its right. The metal is generated art
/// (`refresh-dial`, `refresh-cap`, `refresh-bezel`, `refresh-handle`); the graduations are drawn here so they stay
/// exact, and the light is a fixed layer over the turning metal so the sheen stays put like on real
/// brushed steel. Reduce Motion keeps the dial still and only fades the drawing in and out.
struct VaultDialHeader: View {
    static let height: CGFloat = 140
    /// How long the closing beat plays (dial back to 0, handle turns, drawing leaves).
    static let finish: Duration = .milliseconds(1000)

    var phase: VaultDialPhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorScheme) private var scheme

    /// The door (`refresh-door`: bezel and face, still) and the six-spoke wheel (`refresh-wheel`)
    /// that turns over it. Both have a light and a dark appearance in the catalog.
    private static let door: CGFloat = 116
    private static let wheel: CGFloat = 78

    /// The dial's turn, in degrees, for a pull at `k` (1 = threshold): most of a turn clockwise.
    static func pullAngle(_ k: CGFloat) -> CGFloat { max(0, k) * 300 }

    private var animating: Bool { if case .pulling = phase { false } else { true } }

    var body: some View {
        TimelineView(.animation(paused: !animating)) { timeline in
            let s = state(at: timeline.date)
            vault(wheelAngle: s.dial + s.handle, open: s.open)
                .scaleEffect(s.scale)
                .opacity(s.alpha)
                .offset(y: s.lift)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .accessibilityHidden(true)
    }

    // MARK: Pieces

    private func vault(wheelAngle: CGFloat, open: CGFloat) -> some View {
        ZStack {
            Image("refresh-door")
                .resizable()
                .frame(width: Self.door, height: Self.door)
                .shadow(color: .black.opacity(scheme == .dark ? 0.55 : 0.18), radius: 10, y: 6)
            // The keyhole's light as the lock opens: a soft indigo bloom under the wheel's hub.
            Circle()
                .fill(RadialGradient(colors: [Theme.accent.opacity(0.55), Theme.accent.opacity(0)],
                                     center: .center, startRadius: 0, endRadius: Self.wheel * 0.42))
                .frame(width: Self.wheel, height: Self.wheel)
                .opacity(open)
                .blendMode(scheme == .dark ? .plusLighter : .normal)
            Image("refresh-wheel")
                .resizable()
                .frame(width: Self.wheel, height: Self.wheel)
                .rotationEffect(.degrees(wheelAngle))
                .shadow(color: .black.opacity(scheme == .dark ? 0.5 : 0.22), radius: 3, y: 2)
        }
    }

    // MARK: Motion

    private struct Pose {
        var dial: CGFloat = 0, handle: CGFloat = 0, open: CGFloat = 0
        var alpha: CGFloat = 1, scale: CGFloat = 1, lift: CGFloat = 0
    }

    private enum Curve {
        static func clamp(_ v: CGFloat) -> CGFloat { min(1, max(0, v)) }
        static func out(_ k: CGFloat) -> CGFloat { 1 - pow(1 - k, 3) }
        static func inOut(_ k: CGFloat) -> CGFloat { k < 0.5 ? 4 * k * k * k : 1 - pow(-2 * k + 2, 3) / 2 }
        /// Ease out with a small overshoot, the way a heavy dial settles on its number.
        static func settle(_ k: CGFloat) -> CGFloat {
            let c1: CGFloat = 1.2, c3 = c1 + 1
            return 1 + c3 * pow(k - 1, 3) + c1 * pow(k - 1, 2)
        }
    }

    /// The combination, as (seconds turning, degrees, seconds resting on the number): right past two
    /// numbers, left, right, then again from the top. Negative degrees turn counterclockwise.
    private static let moves: [(CGFloat, CGFloat, CGFloat)] = [(0.85, -430, 0.22), (0.7, 250, 0.2), (0.5, -118, 0.32)]
    private static let loop = moves.reduce(0) { $0 + $1.0 + $1.2 }
    private static let loopTurn = moves.reduce(0) { $0 + $1.1 }

    /// The dial's angle `t` seconds into the combination, starting from the pull's last angle.
    private static func combination(_ t: CGFloat) -> CGFloat {
        let laps = floor(t / loop)
        var local = t - laps * loop, angle = pullAngle(1) + laps * loopTurn
        for (turn, by, rest) in moves {
            if local < turn { return angle + by * Curve.settle(local / turn) }
            angle += by
            local -= turn
            if local < rest { return angle }
            local -= rest
        }
        return angle
    }

    private func state(at now: Date) -> Pose {
        typealias C = Curve
        var p = Pose()
        switch phase {
        case .pulling(let k):
            p.alpha = C.clamp(k * 1.7)
            p.scale = 0.82 + 0.18 * C.out(C.clamp(k))
            p.dial = reduceMotion ? 0 : Self.pullAngle(k)
        case .refreshing(let since):
            p.dial = reduceMotion ? 0 : Self.combination(CGFloat(now.timeIntervalSince(since)))
        case .finishing(let since, let refreshed):
            let s = CGFloat(now.timeIntervalSince(since))
            if reduceMotion {
                p.open = C.clamp(s / 0.2)
                p.alpha = 1 - C.clamp((s - 0.4) / 0.5)
                return p
            }
            // Back to the nearest 0 the short way, then the handle throws the bolts.
            let from = Self.combination(CGFloat(since.timeIntervalSince(refreshed)))
            let home = (from / 360).rounded() * 360
            p.dial = from + (home - from) * C.settle(C.clamp(s / 0.36))
            p.open = C.clamp((s - 0.3) / 0.12)
            p.handle = 90 * C.settle(C.clamp((s - 0.34) / 0.3))
            let leave = C.inOut(C.clamp((s - 0.68) / 0.32))
            p.alpha = 1 - leave
            p.lift = -leave * 18
            p.scale = 1 - leave * 0.06
        }
        return p
    }
}

#endif
