/// The Penpot main component a SwiftUI view draws. `dbridge drift` reads these declarations from
/// source (`static let penpot = PenpotComponent(...)`) and reports Penpot components with no view,
/// views whose path is gone, and props one side has and the other does not. Keys are Swift
/// parameters; values name the Penpot layer (or the variant axis) they drive.
public struct PenpotComponent: Sendable, Equatable {
    public enum Prop: Sendable, Equatable {
        /// A text layer of the main component.
        case text(String)
        /// A nested instance the caller swaps (a glyph, a lead).
        case swap(String)
        /// A layer whose fill the caller picks; `(root)` is the component itself.
        case fill(String)
        /// A variant axis and the values this view covers.
        case variant(String, [String])
    }

    /// Penpot path, `/` separated, spaces trimmed (`Row/Menu`, `Button/Icon`).
    public let path: String
    public let props: [String: Prop]

    public init(path: String, props: [String: Prop] = [:]) {
        self.path = path
        self.props = props
    }
}

/// A view that draws one Penpot main component (or one family of variants). The mapping is plain
/// data, so conformances are `nonisolated` on main-actor views:
///
/// ```swift
/// extension MenuRow: nonisolated PenpotMapped {
///     nonisolated public static let penpot = PenpotComponent(path: "Row/Menu", props: ["title": .text("Title")])
/// }
/// ```
public protocol PenpotMapped {
    static var penpot: PenpotComponent { get }
}
