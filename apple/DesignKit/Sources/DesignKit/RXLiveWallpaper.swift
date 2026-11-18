import SwiftUI

/// Brings a wallpaper to life. Two motions:
/// - a slow camera move on every picture: it zooms in and out a little and pans, a cycle of about
///   forty seconds, so the motion reads at a glance without pulling the eye;
/// - the flow (`rxWallpaperFlow` in RXWallpaperFlow.metal) on drawn pictures only: the colours
///   flow in place. A photo (Landscape, an imported one) keeps its shapes, trees never wobble.
/// Still when Reduce Motion is on, when `active` is false (the picture is off screen) and in
/// Penpot, which keeps one still frame per wallpaper.
public struct RXLiveWallpaper: ViewModifier {
    private let active: Bool
    private let flow: Bool
    /// The largest flow offset, in points.
    public static let amplitude: CGFloat = 16
    /// The camera: the smallest zoom (it always covers the pan), its swing, and the pan as a
    /// fraction of the side.
    static let baseZoom: CGFloat = 1.06
    static let zoomSwing: CGFloat = 0.05
    static let pan: CGFloat = 0.02
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var start = Date.now

    public init(active: Bool = true, flow: Bool = true) {
        self.active = active
        self.flow = flow
    }

    public func body(content: Content) -> some View {
        #if os(watchOS)
        // No SwiftUI shaders on the Watch.
        content
        #else
        if reduceMotion || !active {
            content
        } else {
            TimelineView(.animation(minimumInterval: 1 / 30)) { context in
                let time = context.date.timeIntervalSince(start)
                content
                    .visualEffect { [flow] view, proxy in
                        view.distortionEffect(
                            ShaderLibrary.bundle(.module).rxWallpaperFlow(
                                .float(Float(time)), .float2(proxy.size), .float(Float(Self.amplitude))),
                            maxSampleOffset: CGSize(width: Self.amplitude, height: Self.amplitude),
                            isEnabled: flow)
                        .scaleEffect(Self.zoom(at: time, size: proxy.size, flow: flow))
                        .offset(Self.offset(at: time, size: proxy.size))
                    }
            }
        }
        #endif
    }

    /// Zoom at `time`: never below `baseZoom`, so the pan never shows an edge. With the flow on,
    /// a hair more, so its still edges sit outside the frame that clips the picture.
    static func zoom(at time: TimeInterval, size: CGSize, flow: Bool) -> CGFloat {
        let swing = zoomSwing * (0.5 + 0.5 * sin(time * 2 * .pi / 41))
        let edge = flow ? 2 * amplitude / max(min(size.width, size.height), 1) : 0
        return baseZoom + swing + edge
    }

    /// Pan at `time`, on two slow sines of different periods, so the path never repeats exactly.
    static func offset(at time: TimeInterval, size: CGSize) -> CGSize {
        CGSize(width: size.width * pan * sin(time * 2 * .pi / 53),
               height: size.height * pan * 0.75 * cos(time * 2 * .pi / 47))
    }
}

public extension View {
    /// The slow motion of the RX wallpapers (`RXLiveWallpaper`). `flow` false for photos.
    func rxLiveWallpaper(active: Bool = true, flow: Bool = true) -> some View {
        modifier(RXLiveWallpaper(active: active, flow: flow))
    }
}
