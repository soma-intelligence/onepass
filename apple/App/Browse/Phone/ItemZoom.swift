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

    /// A row, tile or card that pushes `route`: the pushed page zooms out of it.
    func routeZoomSource(_ route: PhoneRoute) -> some View {
        modifier(RouteZoomSource(route: route))
    }

    /// Any view that pushes a page (Réglages rows, perk tiles, the plan card): marked with `id` in
    /// the namespace of the environment, nothing without one.
    func zoomSource<ID: Hashable>(_ id: ID) -> some View {
        modifier(ZoomSource(id: id))
    }

    /// The page pushed from `zoomSource(id)`: it zooms out of that view, and back in when it closes.
    func zoomDestination<ID: Hashable>(_ id: ID) -> some View {
        modifier(ZoomDestination(id: id))
    }

    /// The item detail of `ref`: it zooms out of its row, and back in when it closes.
    func itemZoomDestination(_ ref: ItemRef, in namespace: Namespace.ID) -> some View {
        navigationTransition(.zoom(sourceID: ref, in: namespace))
    }
}

private struct RouteZoomSource: ViewModifier {
    let route: PhoneRoute
    @Environment(\.itemZoomNamespace) private var namespace

    func body(content: Content) -> some View {
        if let namespace {
            content.matchedTransitionSource(id: route, in: namespace)
        } else {
            content
        }
    }
}

private struct ZoomSource<ID: Hashable>: ViewModifier {
    let id: ID
    @Environment(\.itemZoomNamespace) private var namespace

    func body(content: Content) -> some View {
        if let namespace {
            content.matchedTransitionSource(id: id, in: namespace)
        } else {
            content
        }
    }
}

private struct ZoomDestination<ID: Hashable>: ViewModifier {
    let id: ID
    @Environment(\.itemZoomNamespace) private var namespace

    func body(content: Content) -> some View {
        if let namespace {
            content.navigationTransition(.zoom(sourceID: id, in: namespace))
        } else {
            content
        }
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
