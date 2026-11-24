import AppKit
import FillKit
import OnePassCore

/// What the picker shows.
enum PickerState {
    case loading
    /// The logins to pick from; `note` says why the list is what it is (no match, URL unreadable).
    case list([FfiFillCandidate], note: String?)
    /// A message, with the one button that helps.
    case message(String, action: PickerAction?)
}

enum PickerAction {
    /// "Ouvrir OnePass": the app is not running or its bridge is down.
    case openApp
    /// The vault is locked: bring the app forward to unlock.
    case unlock
    /// The fill could not reach the field: copy the value instead.
    case copy
}

/// The account list (spec, Picker), opened by the pill or the shortcut: a search field, the
/// candidates, and "Remember for this app" for an app target. A non-activating panel that takes
/// the keyboard without taking the front from the app being filled, kept out of screen capture.
@MainActor
final class Picker: NSObject, NSSearchFieldDelegate, NSTableViewDataSource, NSTableViewDelegate, NSWindowDelegate {
    /// The login picked and whether to remember it for the app.
    var onPick: ((FfiFillCandidate, Bool) -> Void)?
    /// The search text, after a short pause in typing.
    var onSearch: ((String) -> Void)?
    var onAction: ((PickerAction) -> Void)?
    /// Closed without a pick (Escape, a click elsewhere).
    var onClose: (() -> Void)?

    private let panel: PickerPanel
    private let search = NSSearchField()
    private let table = NSTableView()
    private let scroll = NSScrollView()
    private let note = NSTextField(wrappingLabelWithString: "")
    private let message = NSTextField(wrappingLabelWithString: "")
    private let actionButton = NSButton(title: "", target: nil, action: nil)
    private let spinner = NSProgressIndicator()
    private let remember = NSButton(checkboxWithTitle: String(localized: "fill.picker.remember"), target: nil, action: nil)
    private var rows: [FfiFillCandidate] = []
    private var action: PickerAction?
    private var searchTask: Task<Void, Never>?
    private var closing = false
    private static let size = CGSize(width: 360, height: 320)

    override init() {
        panel = PickerPanel(
            contentRect: CGRect(origin: .zero, size: Self.size), styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered, defer: true)
        super.init()
        panel.isFloatingPanel = true
        panel.level = .popUpMenu
        panel.hidesOnDeactivate = false
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.sharingType = .none
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient, .ignoresCycle]
        panel.delegate = self
        panel.onCancel = { [weak self] in self?.dismiss() }
        build()
    }

    var isOpen: Bool { panel.isVisible }

    /// Opens near the field (`AXFrame`, top-left coordinates), or centred on the screen with the
    /// mouse. `rememberShown`: an app target (a page has no remember). `query` starts a search.
    func open(near axFrame: CGRect?, rememberShown: Bool, query: String?) {
        closing = false
        remember.isHidden = !rememberShown
        remember.state = .on
        search.stringValue = query ?? ""
        show(.loading)
        panel.setFrame(CGRect(origin: origin(near: axFrame), size: Self.size), display: true)
        // A non-activating panel: the keys come here, the app being filled stays in front.
        panel.makeKeyAndOrderFront(nil)
        panel.makeFirstResponder(search)
    }

    func show(_ state: PickerState) {
        spinner.stopAnimation(nil)
        spinner.isHidden = true
        switch state {
        case .loading:
            rows = []
            setList(visible: false)
            message.isHidden = true
            actionButton.isHidden = true
            spinner.isHidden = false
            spinner.startAnimation(nil)
        case .list(let candidates, let text):
            rows = candidates
            setList(visible: true)
            message.isHidden = !candidates.isEmpty
            message.stringValue = String(localized: "fill.picker.noLogin")
            note.stringValue = text ?? ""
            note.isHidden = text == nil
            actionButton.isHidden = true
            table.reloadData()
            if !rows.isEmpty { table.selectRowIndexes([0], byExtendingSelection: false) }
        case .message(let text, let next):
            rows = []
            setList(visible: false)
            message.isHidden = false
            message.stringValue = text
            action = next
            actionButton.isHidden = next == nil
            actionButton.title = next.map(Self.title(of:)) ?? ""
        }
    }

    /// Puts `text` in the search field, as the query the list shows, without a new search.
    func setQuery(_ text: String) {
        searchTask?.cancel()
        search.stringValue = text
    }

    /// Closes without telling `onClose` (a pick, or the controller's own close).
    func close() {
        closing = true
        searchTask?.cancel()
        panel.orderOut(nil)
        rows = []
        table.reloadData()
    }

    private func dismiss() {
        guard !closing else { return }
        close()
        onClose?()
    }

    private func pick(row: Int) {
        guard rows.indices.contains(row) else { return }
        let candidate = rows[row]
        let keep = !remember.isHidden && remember.state == .on
        close()
        onPick?(candidate, keep)
    }

    // MARK: Layout

    private func build() {
        let content = NSVisualEffectView()
        content.material = .popover
        content.state = .active
        content.blendingMode = .behindWindow
        content.wantsLayer = true
        content.layer?.cornerRadius = 12
        content.layer?.masksToBounds = true

        search.placeholderString = String(localized: "common.search")
        search.delegate = self
        search.sendsSearchStringImmediately = true

        let column = NSTableColumn(identifier: .init("login"))
        table.addTableColumn(column)
        table.headerView = nil
        table.rowHeight = 40
        table.style = .inset
        table.backgroundColor = .clear
        table.dataSource = self
        table.delegate = self
        table.target = self
        // One click on a row is the explicit pick.
        table.action = #selector(rowChosen)
        table.setAccessibilityLabel(String(localized: "fill.picker.listLabel"))
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false

        note.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        note.textColor = .secondaryLabelColor
        note.isHidden = true
        message.alignment = .center
        message.isHidden = true
        actionButton.target = self
        actionButton.action = #selector(actionChosen)
        actionButton.bezelStyle = .push
        actionButton.keyEquivalent = "\r"
        actionButton.isHidden = true
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isHidden = true
        remember.isHidden = true

        let views: [NSView] = [search, note, scroll, message, actionButton, spinner, remember]
        for view in views {
            view.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(view)
        }
        NSLayoutConstraint.activate([
            search.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            search.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            search.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -12),
            note.topAnchor.constraint(equalTo: search.bottomAnchor, constant: 6),
            note.leadingAnchor.constraint(equalTo: search.leadingAnchor),
            note.trailingAnchor.constraint(equalTo: search.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: note.bottomAnchor, constant: 6),
            scroll.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 4),
            scroll.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -4),
            scroll.bottomAnchor.constraint(equalTo: remember.topAnchor, constant: -8),
            message.centerYAnchor.constraint(equalTo: scroll.centerYAnchor, constant: -16),
            message.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
            message.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -24),
            actionButton.topAnchor.constraint(equalTo: message.bottomAnchor, constant: 12),
            actionButton.centerXAnchor.constraint(equalTo: content.centerXAnchor),
            spinner.centerXAnchor.constraint(equalTo: scroll.centerXAnchor),
            spinner.centerYAnchor.constraint(equalTo: scroll.centerYAnchor),
            remember.leadingAnchor.constraint(equalTo: search.leadingAnchor),
            remember.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12),
        ])
        panel.contentView = content
    }

    private func setList(visible: Bool) {
        scroll.isHidden = !visible
        if !visible {
            note.isHidden = true
        }
    }

    private func origin(near axFrame: CGRect?) -> CGPoint {
        let primaryHeight = NSScreen.screens.first?.frame.height ?? 0
        if let axFrame, axFrame != .zero {
            let field = ScreenGeometry.appKitRect(fromAX: axFrame, primaryScreenHeight: primaryHeight)
            let screen = NSScreen.screens.first { $0.frame.contains(CGPoint(x: field.midX, y: field.midY)) } ?? NSScreen.main
            let visible = screen?.visibleFrame ?? field
            // Below the field, right edges aligned; above it when there is no room below.
            var x = field.maxX - Self.size.width
            var y = field.minY - Self.size.height - 6
            if y < visible.minY { y = field.maxY + 6 }
            x = min(max(x, visible.minX), visible.maxX - Self.size.width)
            y = min(max(y, visible.minY), visible.maxY - Self.size.height)
            return CGPoint(x: x, y: y)
        }
        let screen = NSScreen.screens.first { NSMouseInRect(NSEvent.mouseLocation, $0.frame, false) } ?? NSScreen.main
        let visible = screen?.visibleFrame ?? .zero
        return CGPoint(x: visible.midX - Self.size.width / 2, y: visible.midY - Self.size.height / 2)
    }

    private static func title(of action: PickerAction) -> String {
        switch action {
        case .openApp: String(localized: "fill.picker.openApp")
        case .unlock: String(localized: "common.unlock")
        case .copy: String(localized: "common.copy")
        }
    }

    // MARK: Actions

    @objc private func rowChosen() {
        guard table.clickedRow >= 0 else { return }
        pick(row: table.clickedRow)
    }

    @objc private func actionChosen() {
        guard let action else { return }
        onAction?(action)
    }

    func controlTextDidChange(_ notification: Notification) {
        let text = search.stringValue
        searchTask?.cancel()
        searchTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled else { return }
            self?.onSearch?(text)
        }
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
        switch selector {
        case #selector(NSResponder.moveDown(_:)):
            moveSelection(by: 1)
            return true
        case #selector(NSResponder.moveUp(_:)):
            moveSelection(by: -1)
            return true
        case #selector(NSResponder.insertNewline(_:)):
            if !rows.isEmpty, table.selectedRow >= 0 {
                pick(row: table.selectedRow)
            } else if let action {
                onAction?(action)
            }
            return true
        case #selector(NSResponder.cancelOperation(_:)):
            dismiss()
            return true
        default:
            return false
        }
    }

    private func moveSelection(by delta: Int) {
        guard !rows.isEmpty else { return }
        let row = min(max(table.selectedRow + delta, 0), rows.count - 1)
        table.selectRowIndexes([row], byExtendingSelection: false)
        table.scrollRowToVisible(row)
    }

    func windowDidResignKey(_ notification: Notification) {
        dismiss()
    }

    // MARK: Table

    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let id = NSUserInterfaceItemIdentifier("loginRow")
        let cell = (tableView.makeView(withIdentifier: id, owner: nil) as? LoginRow) ?? LoginRow(identifier: id)
        let candidate = rows[row]
        let detail = [candidate.account ?? candidate.subtitle, candidate.vaultName].filter { !$0.isEmpty }
        cell.configure(title: candidate.title, detail: ListFormatter.localizedString(byJoining: detail))
        return cell
    }
}

/// A borderless panel that takes the keyboard (the search field) without activating the helper.
private final class PickerPanel: NSPanel {
    var onCancel: (() -> Void)?
    override var canBecomeKey: Bool { true }
    override func cancelOperation(_ sender: Any?) { onCancel?() }
}

/// One login: its title and, below, its identifier and vault.
private final class LoginRow: NSTableCellView {
    private let title = NSTextField(labelWithString: "")
    private let detail = NSTextField(labelWithString: "")

    init(identifier: NSUserInterfaceItemIdentifier) {
        super.init(frame: .zero)
        self.identifier = identifier
        title.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .medium)
        detail.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        detail.textColor = .secondaryLabelColor
        for label in [title, detail] {
            label.lineBreakMode = .byTruncatingTail
            label.translatesAutoresizingMaskIntoConstraints = false
            addSubview(label)
        }
        NSLayoutConstraint.activate([
            title.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            title.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -8),
            title.topAnchor.constraint(equalTo: topAnchor, constant: 3),
            detail.leadingAnchor.constraint(equalTo: title.leadingAnchor),
            detail.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -8),
            detail.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 1),
        ])
    }

    required init?(coder: NSCoder) { nil }

    func configure(title text: String, detail subtext: String) {
        title.stringValue = text
        detail.stringValue = subtext
        setAccessibilityLabel(subtext.isEmpty ? text : ListFormatter.localizedString(byJoining: [text, subtext]))
    }
}
