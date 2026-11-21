import SwiftUI
#if os(iOS)
import CoreMotion
#endif

/// A light, generic reflection that moves over a document as the phone tilts (spec 2026-11-21
/// section 7.2): a soft diagonal band, no pattern, no symbol, no glow or halo. The iPhone reads
/// device motion at 30 Hz, only between `onAppear` and `onDisappear`; the Mac follows the pointer
/// while it hovers. Reduce Motion freezes it in its resting place.
public struct DocumentSheen: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var systemReduceMotion
    @Environment(\.documentReduceMotion) private var reduceMotionOverride
    /// -1...1 on both axes; zero is the resting place.
    @State private var tilt: CGSize = .zero
    #if os(iOS)
    @State private var motion = SheenMotion()
    #endif

    public init() {}

    private var reduceMotion: Bool { reduceMotionOverride ?? systemReduceMotion }

    /// Where the band sits across the surface for a tilt: 0.5 at rest, kept inside 0.15...0.85.
    static func bandCenter(_ tilt: CGSize) -> UnitPoint {
        let x = min(max(0.5 + tilt.width * 0.35, 0.15), 0.85)
        let y = min(max(0.5 + tilt.height * 0.35, 0.15), 0.85)
        return UnitPoint(x: x, y: y)
    }

    public func body(content: Content) -> some View {
        let center = Self.bandCenter(reduceMotion ? .zero : tilt)
        content
            .overlay {
                LinearGradient(
                    stops: [
                        .init(color: .white.opacity(0), location: max(center.x - 0.28, 0)),
                        .init(color: .white.opacity(0.16), location: center.x),
                        .init(color: .white.opacity(0), location: min(center.x + 0.28, 1)),
                    ],
                    startPoint: UnitPoint(x: 0, y: center.y - 0.5),
                    endPoint: UnitPoint(x: 1, y: center.y + 0.5)
                )
                .blendMode(.softLight)
                .allowsHitTesting(false)
                .accessibilityHidden(true)
            }
            #if os(iOS)
            .onAppear {
                guard !reduceMotion else { return }
                motion.start { tilt = $0 }
            }
            .onDisappear { motion.stop() }
            .onChange(of: reduceMotion) { _, reduced in
                if reduced {
                    motion.stop()
                    tilt = .zero
                } else {
                    motion.start { tilt = $0 }
                }
            }
            #elseif os(macOS)
            .onContinuousHover { phase in
                guard !reduceMotion else { return }
                switch phase {
                case .active(let point):
                    // The pointer's place in the view stands in for the tilt (the view is about
                    // 360 pt wide: a coarse, bounded mapping is enough).
                    withAnimation(.easeOut(duration: 0.2)) {
                        tilt = CGSize(width: (point.x / 180) - 1, height: (point.y / 126) - 1)
                    }
                case .ended:
                    withAnimation(.easeOut(duration: 0.4)) { tilt = .zero }
                }
            }
            #endif
    }
}

extension View {
    /// The document reflection (`DocumentSheen`).
    public func documentSheen() -> some View {
        modifier(DocumentSheen())
    }
}

#if os(iOS)
/// Device motion at 30 Hz while a document is on screen, as a bounded tilt.
@MainActor
final class SheenMotion {
    private let manager = CMMotionManager()

    func start(_ update: @escaping @MainActor (CGSize) -> Void) {
        guard manager.isDeviceMotionAvailable, !manager.isDeviceMotionActive else { return }
        manager.deviceMotionUpdateInterval = 1.0 / 30
        manager.startDeviceMotionUpdates(to: .main) { data, _ in
            guard let attitude = data?.attitude else { return }
            // Roll left and right, pitch around its usual reading angle (about 45 degrees).
            let x = max(min(attitude.roll / 0.6, 1), -1)
            let y = max(min((attitude.pitch - 0.8) / 0.6, 1), -1)
            MainActor.assumeIsolated { update(CGSize(width: x, height: y)) }
        }
    }

    func stop() {
        manager.stopDeviceMotionUpdates()
    }
}
#endif

// MARK: - Reduce Motion override (snapshots)

private struct DocumentReduceMotionKey: EnvironmentKey {
    static let defaultValue: Bool? = nil
}

extension EnvironmentValues {
    /// Forces Reduce Motion for the document renderings (snapshot tests). Nil follows the system.
    var documentReduceMotion: Bool? {
        get { self[DocumentReduceMotionKey.self] }
        set { self[DocumentReduceMotionKey.self] = newValue }
    }
}
