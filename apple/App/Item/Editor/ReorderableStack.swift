import DesignKit
import SwiftUI

/// A vertical stack whose rows move with a ☰ handle (spec 2026-11-13, "Reordering"): the handle
/// starts a vertical drag, the dragged row follows the finger by offset (no shadow), the others
/// slide, and `onMove` runs once on release. VoiceOver moves a row with the handle's "Monter" and
/// "Descendre" actions. One code path for the Mac and the iPhone.
struct ReorderableStack<Item: Identifiable, Row: View>: View where Item.ID: Hashable {
    let items: [Item]
    var spacing: CGFloat = 0
    let accessibilityName: (Item) -> Text
    /// The handle's accessibility identifier (UI tests), none by default.
    var handleIdentifier: (Item) -> String? = { _ in nil }
    let onMove: (_ from: Int, _ to: Int) -> Void
    @ViewBuilder let row: (Item, ReorderHandle) -> Row

    @State private var frames: [Item.ID: CGRect] = [:]
    @State private var dragging: Item.ID?
    @State private var translation: CGFloat = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private let space = "reorderable-stack"

    var body: some View {
        VStack(spacing: spacing) {
            ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                row(item, handle(for: item, at: index))
                    .background {
                        GeometryReader { proxy in
                            Color.clear.preference(
                                key: ReorderFramesKey.self, value: [index: proxy.frame(in: .named(space))])
                        }
                    }
                    .offset(y: offset(of: item, at: index))
                    .zIndex(dragging == item.id ? 1 : 0)
            }
        }
        .coordinateSpace(.named(space))
        .onPreferenceChange(ReorderFramesKey.self) { value in
            var out: [Item.ID: CGRect] = [:]
            for (index, frame) in value { if let item = items[safe: index] { out[item.id] = frame } }
            frames = out
        }
    }

    private func handle(for item: Item, at index: Int) -> ReorderHandle {
        ReorderHandle(
            name: accessibilityName(item),
            identifier: handleIdentifier(item),
            canMoveUp: index > 0,
            canMoveDown: index < items.count - 1,
            onChanged: { y in
                if dragging == nil { dragging = item.id }
                translation = y
            },
            onEnded: {
                let target = targetIndex(from: index)
                withAnimation(reduceMotion ? nil : FoldMotion.animation(reduceMotion: reduceMotion)) {
                    dragging = nil
                    translation = 0
                    if target != index { onMove(index, target) }
                }
            },
            onStep: { delta in
                let target = min(max(index + delta, 0), items.count - 1)
                if target != index { onMove(index, target) }
            })
    }

    /// Where the dragged row lands: as many slots down as other rows have their middle above its
    /// own moved middle.
    private func targetIndex(from index: Int) -> Int {
        guard let id = items[safe: index]?.id, let frame = frames[id] else { return index }
        let middle = frame.midY + translation
        return items.filter { $0.id != id && (frames[$0.id].map { $0.midY < middle } ?? false) }.count
    }

    /// The dragged row follows the drag; the rows it passed slide by its height.
    private func offset(of item: Item, at index: Int) -> CGFloat {
        guard let dragged = dragging, let from = items.firstIndex(where: { $0.id == dragged }) else { return 0 }
        if item.id == dragged { return translation }
        let height = (frames[dragged]?.height ?? 0) + spacing
        let target = targetIndex(from: from)
        let slide: CGFloat
        if from < target, index > from, index <= target {
            slide = -height
        } else if from > target, index < from, index >= target {
            slide = height
        } else {
            slide = 0
        }
        return slide
    }
}

/// Each row's frame, keyed by its position in `items` (an `Int` key keeps the value `Sendable`).
private struct ReorderFramesKey: PreferenceKey {
    static let defaultValue: [Int: CGRect] = [:]
    static func reduce(value: inout [Int: CGRect], nextValue: () -> [Int: CGRect]) {
        value.merge(nextValue()) { $1 }
    }
}

/// The ☰ handle of a movable row or card: drag to move, or VoiceOver's "Monter" and "Descendre".
struct ReorderHandle: View {
    let name: Text
    var identifier: String?
    let canMoveUp: Bool
    let canMoveDown: Bool
    let onChanged: (CGFloat) -> Void
    let onEnded: () -> Void
    let onStep: (Int) -> Void

    var body: some View {
        Image(systemName: "line.3.horizontal")
            .font(.body.weight(.medium))
            .foregroundStyle(.secondary)
            .frame(width: 28, height: 44)
            .contentShape(.rect)
            #if os(macOS)
            .pointerStyle(.grabIdle)
            #endif
            .gesture(
                DragGesture(minimumDistance: 2, coordinateSpace: .global)
                    .onChanged { onChanged($0.translation.height) }
                    .onEnded { _ in onEnded() })
            .accessibilityElement()
            .accessibilityLabel(Text("editor.reorder.label \(name)"))
            .accessibilityIdentifier(identifier ?? "")
            .accessibilityAction(named: Text("editor.reorder.up")) { if canMoveUp { onStep(-1) } }
            .accessibilityAction(named: Text("editor.reorder.down")) { if canMoveDown { onStep(1) } }
    }
}
