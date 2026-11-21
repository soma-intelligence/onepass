import SwiftUI
#if os(iOS)
import CoreMotion
#endif

/// A light, generic reflection that moves over a document as the phone tilts (spec 2026-11-21
/// section 7.2): a soft diagonal band, no pattern, no symbol, no glow or halo. DesignKit has no
/// brushed texture to build on, so the band is a plain gradient. The iPhone reads device motion at
/// 30 Hz, only between `onAppear` and `onDisappear`, through one shared motion manager; the Mac
/// follows the pointer while it hovers. Reduce Motion freezes it in its resting place.
public struct DocumentSheen: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var systemReduceMotion
    @Environment(\.documentReduceMotion) private var reduceMotionOverride
    /// -1...1 on both axes; zero is the resting place.
    @State private var tilt: CGSize = .zero
    #if os(iOS)
    /// This view's subscription to the shared motion feed (a value: nothing is allocated here).
    @State private var subscription = UUID()
    #elseif os(macOS)
    @State private var size: CGSize = .zero
    #endif
    private let cornerRadius: CGFloat

    /// `cornerRadius`: the band stays inside the document's rounded frame.
    public init(cornerRadius: CGFloat = 0) {
        self.cornerRadius = cornerRadius
    }

    private var reduceMotion: Bool { reduceMotionOverride ?? systemReduceMotion }

    /// Where the band sits across the surface for a tilt: 0.5 at rest, kept inside 0.15...0.85.
    static func bandCenter(_ tilt: CGSize) -> UnitPoint {
        let x = min(max(0.5 + tilt.width * 0.35, 0.15), 0.85)
        let y = min(max(0.5 + tilt.height * 0.35, 0.15), 0.85)
        return UnitPoint(x: x, y: y)
    }

    /// The tilt the pointer at `point` stands for in a view of `size`: -1 at the leading or top
    /// edge, 1 at the other one.
    static func pointerTilt(_ point: CGPoint, in size: CGSize) -> CGSize {
        guard size.width > 0, size.height > 0 else { return .zero }
        func axis(_ v: CGFloat, _ length: CGFloat) -> CGFloat { min(max(v / length * 2 - 1, -1), 1) }
        return CGSize(width: axis(point.x, size.width), height: axis(point.y, size.height))
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
                .clipShape(.rect(cornerRadius: cornerRadius, style: .continuous))
                .allowsHitTesting(false)
                .accessibilityHidden(true)
            }
            #if os(iOS)
            .onAppear { follow(!reduceMotion) }
            .onDisappear { follow(false) }
            .onChange(of: reduceMotion) { _, reduced in follow(!reduced) }
            #elseif os(macOS)
            .onGeometryChange(for: CGSize.self) { $0.size } action: { size = $0 }
            .onContinuousHover { phase in
                guard !reduceMotion else { return }
                switch phase {
                case .active(let point):
                    withAnimation(.easeOut(duration: 0.2)) { tilt = Self.pointerTilt(point, in: size) }
                case .ended:
                    withAnimation(.easeOut(duration: 0.4)) { tilt = .zero }
                }
            }
            #endif
    }

    #if os(iOS)
    private func follow(_ on: Bool) {
        if on {
            SheenMotion.shared.add(subscription) { tilt = $0 }
        } else {
            SheenMotion.shared.remove(subscription)
            tilt = .zero
        }
    }
    #endif
}

extension View {
    /// The document reflection (`DocumentSheen`), square corners.
    public func documentSheen() -> some View {
        modifier(DocumentSheen())
    }
}

#if os(iOS)
/// The one device-motion feed of the document reflections: a single `CMMotionManager`, created on
/// the first subscription, updating at 30 Hz while at least one document is on screen.
@MainActor
final class SheenMotion {
    static let shared = SheenMotion()

    private var manager: CMMotionManager?
    private var subscribers: [UUID: @MainActor (CGSize) -> Void] = [:]

    var isRunning: Bool { manager?.isDeviceMotionActive ?? false }
    var subscriberCount: Int { subscribers.count }

    func add(_ id: UUID, _ update: @escaping @MainActor (CGSize) -> Void) {
        subscribers[id] = update
        let manager = manager ?? CMMotionManager()
        self.manager = manager
        guard manager.isDeviceMotionAvailable, !manager.isDeviceMotionActive else { return }
        manager.deviceMotionUpdateInterval = 1.0 / 30
        manager.startDeviceMotionUpdates(to: .main) { [weak self] data, _ in
            guard let attitude = data?.attitude else { return }
            // Roll left and right, pitch around its usual reading angle (about 45 degrees).
            let x = max(min(attitude.roll / 0.6, 1), -1)
            let y = max(min((attitude.pitch - 0.8) / 0.6, 1), -1)
            MainActor.assumeIsolated {
                guard let self else { return }
                for update in self.subscribers.values { update(CGSize(width: x, height: y)) }
            }
        }
    }

    func remove(_ id: UUID) {
        subscribers[id] = nil
        if subscribers.isEmpty { manager?.stopDeviceMotionUpdates() }
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
