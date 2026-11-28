#if os(iOS)
import SwiftUI
import UIKit

/// A large title with a search field always shown under it (`.searchable` with
/// `.navigationBarDrawer(displayMode: .always)`) on the root of a tab's navigation stack.
///
/// UIKit lays such a bar out collapsed on its first display: the scroll view rests at its top,
/// but the bar keeps the compact height (108 pt instead of 160 on a 402 pt iPhone, measured on the
/// iOS 27.2 simulator), so the title sits small in the bar until a pull, a tab switch or a sheet re-lays it out.
/// The same happens with a bare `TabView` > `NavigationStack` > `List`, so nothing in the screen
/// causes it. And SwiftUI's `scrollTo(edge: .top)` stops at the compact bar's inset, so a tap on
/// the selected tab came back to the top with the title still folded.
///
/// This modifier fixes both through the bar the screen already has:
/// - on display, a page resting at its top gets its bar sized to fit (the large title);
/// - each change of `scrollToTop` scrolls to the top of the expanded bar, the way a pull does,
///   so the title unfolds on the way up.
extension View {
    public func expandsLargeTitle(scrollToTop: Int = 0, enabled: Bool = true) -> some View {
        modifier(LargeTitleExpansion(scrollToTop: scrollToTop, enabled: enabled))
    }
}

struct LargeTitleExpansion: ViewModifier {
    let scrollToTop: Int
    let enabled: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content.background {
            LargeTitleAnchor(scrollToTop: scrollToTop, enabled: enabled, animated: !reduceMotion)
                .frame(width: 0, height: 0)
                .accessibilityHidden(true)
        }
    }
}

private struct LargeTitleAnchor: UIViewRepresentable {
    let scrollToTop: Int
    let enabled: Bool
    let animated: Bool

    func makeUIView(context: Context) -> AnchorView {
        let view = AnchorView()
        view.isUserInteractionEnabled = false
        view.scrollToTop = scrollToTop
        return view
    }

    func updateUIView(_ view: AnchorView, context: Context) {
        view.enabled = enabled
        if view.scrollToTop != scrollToTop {
            view.scrollToTop = scrollToTop
            if enabled { view.scrollToExpandedTop(animated: animated) }
        }
    }

    final class AnchorView: UIView {
        var scrollToTop = 0
        var enabled = true

        override func didMoveToWindow() {
            super.didMoveToWindow()
            guard window != nil else { return }
            // After this layout pass: the bar and the scroll view have their first frames then.
            DispatchQueue.main.async { [weak self] in self?.expandIfResting() }
        }

        /// The view controller of the screen and its navigation controller.
        private var screen: (UIViewController, UINavigationController)? {
            var responder: UIResponder? = self
            while let next = responder?.next {
                if let controller = next as? UIViewController, let navigation = controller.navigationController {
                    return (controller, navigation)
                }
                responder = next
            }
            return nil
        }

        /// The scroll view the bar follows: the one UIKit was told about, else the screen's first
        /// vertical scroll view.
        private func scrollView(of controller: UIViewController) -> UIScrollView? {
            if let observed = controller.contentScrollView(for: .top) { return observed }
            var queue: [UIView] = [controller.view]
            while !queue.isEmpty {
                let view = queue.removeFirst()
                if let scroll = view as? UIScrollView, scroll.bounds.height > 0,
                    scroll.contentSize.height >= scroll.contentSize.width {
                    return scroll
                }
                queue.append(contentsOf: view.subviews)
            }
            return nil
        }

        /// The points the bar still has to grow to show its large title.
        private func missingHeight(of bar: UINavigationBar) -> CGFloat {
            let fit = bar.sizeThatFits(CGSize(width: bar.bounds.width, height: .greatestFiniteMagnitude))
            return max(0, fit.height - bar.bounds.height)
        }

        /// The first display: a page at its top under a folded bar gets the large title.
        func expandIfResting() {
            guard enabled, let (controller, navigation) = screen,
                controller.navigationItem.largeTitleDisplayMode != .never,
                let scroll = scrollView(of: controller)
            else { return }
            let bar = navigation.navigationBar
            let atTop = scroll.contentOffset.y <= -scroll.adjustedContentInset.top + 0.5
            guard atTop, missingHeight(of: bar) > 0.5 else { return }
            bar.sizeToFit()
        }

        /// A tap on the selected tab: up to the top of the expanded bar, so the title unfolds.
        func scrollToExpandedTop(animated: Bool) {
            guard let (controller, navigation) = screen, let scroll = scrollView(of: controller) else { return }
            let missing = controller.navigationItem.largeTitleDisplayMode == .never ? 0 : missingHeight(of: navigation.navigationBar)
            let top = -(scroll.adjustedContentInset.top + missing)
            scroll.setContentOffset(CGPoint(x: scroll.contentOffset.x, y: top), animated: animated)
        }
    }
}
#endif
