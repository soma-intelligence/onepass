#include <metal_stdlib>
using namespace metal;

/// The slow drift of the RX wallpapers (`RXLiveWallpaper`): each point of the picture is read from
/// a place that wanders on two crossed sine fields, so colours flow without the picture moving.
/// `size` is the layer's size in points, `amp` the largest offset. The offset fades to nothing
/// toward the edges (always less than the distance to the edge), so nothing outside the picture
/// is ever read.
[[ stitchable ]] float2 rxWallpaperFlow(float2 position, float time, float2 size, float amp) {
    float2 uv = position / max(size, float2(1.0));
    float dx = sin(uv.y * 3.1 + time * 0.35) + 0.6 * sin(uv.x * 2.3 - time * 0.27 + uv.y * 1.7);
    float dy = cos(uv.x * 2.7 + time * 0.31) + 0.6 * sin(uv.y * 1.9 + time * 0.22 - uv.x * 1.3);
    float2 edge = min(position, size - position) / (2.5 * max(amp, 1.0));
    float2 fade = smoothstep(0.0, 1.0, clamp(edge, 0.0, 1.0));
    float2 moved = position + amp * fade * float2(dx, dy) / 1.6;
    return clamp(moved, float2(0.0), size);
}
