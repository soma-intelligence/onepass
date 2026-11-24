import AppKit
import FillKit

/// The small key next to a password field (spec, Pill): a borderless, non-activating panel kept
/// out of screen capture, glued to the field's trailing edge. A click opens the picker. It also
/// shows a short message near the field ("Copied, paste with ⌘V", "Fill stopped").
@MainActor
final class Pill {
    var onClick: (() -> Void)?

    private let panel: NSPanel
    private let button: NSButton
    private let label: NSTextField
    private var messageTask: Task<Void, Never>?
    private static let size = CGSize(width: 24, height: 24)

    init() {
        panel = Self.makePanel(size: Self.size)
        button = NSButton(
            image: NSImage(systemSymbolName: "key.fill", accessibilityDescription: nil) ?? NSImage(),
            target: nil, action: nil)
        label = NSTextField(labelWithString: "")
        button.target = self
        button.action = #selector(clicked)
        button.isBordered = false
        button.contentTintColor = .labelColor
        button.toolTip = String(localized: "fill.pill.help")
        button.setAccessibilityLabel(String(localized: "fill.pill.help"))
        label.font = .systemFont(ofSize: NSFont.smallSystemFontSize, weight: .medium)
        label.lineBreakMode = .byTruncatingTail
        label.isHidden = true
        let content = Self.background()
        for view in [button, label] {
            view.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(view)
        }
        NSLayoutConstraint.activate([
            button.centerXAnchor.constraint(equalTo: content.centerXAnchor),
            button.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            label.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 10),
            label.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -10),
            label.centerYAnchor.constraint(equalTo: content.centerYAnchor),
        ])
        panel.contentView = content
    }

    var isVisible: Bool { panel.isVisible }

    /// Shows the key at `axFrame`, the field's `AXFrame` (top-left coordinates).
    func show(at axFrame: CGRect) {
        guard messageTask == nil else { return }
        button.isHidden = false
        label.isHidden = true
        place(Self.size, at: axFrame)
        panel.orderFrontRegardless()
    }

    /// Follows the field when it moves or scrolls.
    func move(to axFrame: CGRect) {
        guard panel.isVisible, messageTask == nil else { return }
        place(panel.frame.size, at: axFrame)
    }

    func hide() {
        guard messageTask == nil else { return }
        panel.orderOut(nil)
    }

    /// A message for a few seconds, at the field when its frame is known, else at the top of the
    /// screen with the mouse.
    func flash(_ text: String, near axFrame: CGRect?) {
        messageTask?.cancel()
        button.isHidden = true
        label.isHidden = false
        label.stringValue = text
        let width = min(max(label.intrinsicContentSize.width + 20, 80), 420)
        let size = CGSize(width: width, height: 26)
        if let axFrame, axFrame != .zero {
            place(size, at: axFrame)
        } else {
            let screen = NSScreen.screens.first { NSMouseInRect(NSEvent.mouseLocation, $0.frame, false) } ?? NSScreen.main
            let visible = screen?.visibleFrame ?? .zero
            panel.setFrame(
                CGRect(x: visible.midX - width / 2, y: visible.maxY - size.height - 12, width: width, height: size.height),
                display: true)
        }
        panel.orderFrontRegardless()
        NSAccessibility.post(
            element: panel, notification: .announcementRequested,
            userInfo: [.announcement: text, .priority: NSAccessibilityPriorityLevel.high.rawValue])
        messageTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard let self, !Task.isCancelled else { return }
            self.messageTask = nil
            self.panel.orderOut(nil)
        }
    }

    /// Places a panel of `size` against the trailing edge of the field, on the field's screen.
    /// `AXFrame` is flipped around the main screen's height (the screen at the AppKit origin),
    /// which converts a frame on any screen of the arrangement.
    private func place(_ size: CGSize, at axFrame: CGRect) {
        let primaryHeight = NSScreen.screens.first?.frame.height ?? 0
        let field = ScreenGeometry.appKitRect(fromAX: axFrame, primaryScreenHeight: primaryHeight)
        let center = CGPoint(x: field.midX, y: field.midY)
        let screen = NSScreen.screens.first { $0.frame.contains(center) } ?? NSScreen.main
        let visible = screen?.visibleFrame ?? field
        let origin = ScreenGeometry.pillOrigin(field: field, pill: size, visible: visible)
        panel.setFrame(CGRect(origin: origin, size: size), display: true)
    }

    @objc private func clicked() {
        onClick?()
    }

    private static func makePanel(size: CGSize) -> NSPanel {
        let panel = NSPanel(
            contentRect: CGRect(origin: .zero, size: size), styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered, defer: true)
        panel.isFloatingPanel = true
        panel.level = .popUpMenu
        panel.hidesOnDeactivate = false
        panel.becomesKeyOnlyIfNeeded = true
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.sharingType = .none
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient, .ignoresCycle]
        return panel
    }

    private static func background() -> NSView {
        let view = NSVisualEffectView()
        view.material = .popover
        view.state = .active
        view.blendingMode = .behindWindow
        view.wantsLayer = true
        view.layer?.cornerRadius = 7
        view.layer?.masksToBounds = true
        return view
    }
}
