import Foundation

/// Matches reference exports with app screenshots by file name.
///
/// `Settings@3x.png`, `settings.png` and `Settings.PNG` all map to the key `settings`, so a
/// Penpot export and a simulator screenshot pair up without renaming.
public enum Pairing {
    public struct Pair: Sendable, Equatable {
        public var name: String
        public var reference: URL?
        public var candidate: URL?
    }

    public static let imageExtensions: Set<String> = ["png", "jpg", "jpeg", "heic", "tif", "tiff"]

    public static func key(for url: URL) -> String {
        var base = url.deletingPathExtension().lastPathComponent
        for suffix in ["@1x", "@2x", "@3x"] where base.hasSuffix(suffix) {
            base.removeLast(suffix.count)
        }
        return base.lowercased()
    }

    public static func images(in directory: URL) throws -> [URL] {
        let fm = FileManager.default
        guard let e = fm.enumerator(at: directory, includingPropertiesForKeys: nil) else {
            throw DBDiffError.io("cannot list \(directory.path)")
        }
        var out: [URL] = []
        for case let url as URL in e where imageExtensions.contains(url.pathExtension.lowercased()) {
            out.append(url)
        }
        return out.sorted { $0.path < $1.path }
    }

    /// Every key found on either side, sorted. A missing side is nil.
    public static func pairs(references: [URL], candidates: [URL]) -> [Pair] {
        var refs: [String: URL] = [:]
        var cands: [String: URL] = [:]
        var names: [String: String] = [:]
        for r in references {
            let k = key(for: r)
            refs[k] = r
            names[k] = names[k] ?? r.deletingPathExtension().lastPathComponent.replacingOccurrences(of: "@3x", with: "")
        }
        for c in candidates {
            let k = key(for: c)
            cands[k] = c
            names[k] = names[k] ?? c.deletingPathExtension().lastPathComponent
        }
        return Set(refs.keys).union(cands.keys).sorted().map {
            Pair(name: names[$0] ?? $0, reference: refs[$0], candidate: cands[$0])
        }
    }
}
