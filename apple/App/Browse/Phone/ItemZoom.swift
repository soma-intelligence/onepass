#if os(iOS)
import SwiftUI
import VaultKit

/// iPhone: an item opens by zooming out of the row that was tapped, and closes back into it.
/// PhoneTabsView owns the namespace and hands it down its navigation stacks; every row that pushes
/// `PhoneRoute.item` marks itself as the source, the item detail as the destination.
extension EnvironmentValues {
    @Entry var itemZoomNamespace: Namespace.ID?
}

extension View {
    /// Marks a row that opens `ref` as where its zoom starts.
    func itemZoomSource(_ ref: ItemRef) -> some View {
        modifier(ItemZoomSource(ref: ref))
    }

    /// The item detail of `ref`: it zooms out of its row, and back in when it closes.
    func itemZoomDestination(_ ref: ItemRef, in namespace: Namespace.ID) -> some View {
        navigationTransition(.zoom(sourceID: ref, in: namespace))
    }
}

private struct ItemZoomSource: ViewModifier {
    let ref: ItemRef
    @Environment(\.itemZoomNamespace) private var namespace

    func body(content: Content) -> some View {
        if let namespace {
            content.matchedTransitionSource(id: ref, in: namespace)
        } else {
            content
        }
    }
}
#endif
