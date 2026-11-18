import SwiftUI

/// Makes a wallpaper drift slowly (`rxWallpaperFlow` in RXWallpaperFlow.metal): the colours flow
/// in place, a full cycle takes about half a minute. Still when Reduce Motion is on, when `active`
/// is false (the picture is off screen) and in Penpot, which keeps one still frame per wallpaper.
public struct RXLiveWallpaper: ViewModifier {
    private let active: Bool
    /// The largest offset, in points.
    public static let amplitude: CGFloat = 16
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var start = Date.now

    public init(active: Bool = true) { self.active = active }

    public func body(content: Content) -> some View {
        #if os(watchOS)
        // No SwiftUI shaders on the Watch.
        content
        #else
        if reduceMotion || !active {
            content
        } else {
            TimelineView(.animation(minimumInterval: 1 / 30)) { context in
                let time = Float(context.date.timeIntervalSince(start))
                content
                    .visualEffect { view, proxy in
                        view.distortionEffect(
                            ShaderLibrary.bundle(.module).rxWallpaperFlow(
                                .float(time), .float2(proxy.size), .float(Float(Self.amplitude))),
                            maxSampleOffset: CGSize(width: Self.amplitude, height: Self.amplitude))
                        // A hair larger, so the still edges sit outside the frame that clips it.
                        .scaleEffect(1 + 2 * Self.amplitude / max(min(proxy.size.width, proxy.size.height), 1))
                    }
            }
        }
        #endif
    }
}

public extension View {
    /// The slow drift of the RX wallpapers (`RXLiveWallpaper`).
    func rxLiveWallpaper(active: Bool = true) -> some View {
        modifier(RXLiveWallpaper(active: active))
    }
}
