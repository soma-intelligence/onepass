#if DEBUG
import Foundation

/// Debug builds only: `-OnePassFillTestLog <path>` makes the helper append one line per event to
/// that file, for `FillAnywhereUITests` (a test runner cannot read the helper's `os_log`). Lines:
/// `trusted=<true|false>` (the Accessibility grant, at launch and on each change),
/// `bridge=<status>` (the first bridge status), `pill=<kind>` (the pill shown next to a field) and
/// `strategy=<name>` (the strategy that filled a value). Never a value, a title or an account.
/// Release builds have neither the argument nor this file.
enum FillTestLog {
    /// The file, from the launch argument; nil when the hook is off.
    static let path: String? = {
        let value = UserDefaults.standard.string(forKey: "OnePassFillTestLog")
        return value?.isEmpty == false ? value : nil
    }()

    static var isActive: Bool { path != nil }

    static func append(_ line: String) {
        guard let path else { return }
        let data = Data((line + "\n").utf8)
        if let handle = FileHandle(forWritingAtPath: path) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
        } else {
            FileManager.default.createFile(atPath: path, contents: data)
        }
    }
}
#endif
