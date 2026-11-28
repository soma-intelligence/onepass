import CoreGraphics
import Foundation

/// Attributes of one focused element, read once by the helper. Fixtures decode it from JSON, so
/// every field except `bundleID` may be missing.
public struct FieldSnapshot: Codable, Sendable, Equatable {
    public var role: String?
    public var subrole: String?
    public var title: String?
    public var placeholder: String?
    public var label: String?
    public var domIdentifier: String?
    public var domClasses: [String]
    public var frame: CGRect
    public var pid: Int32
    public var bundleID: String
    public var windowTitle: String?
    public var url: URL?

    public init(
        role: String? = nil, subrole: String? = nil, title: String? = nil,
        placeholder: String? = nil, label: String? = nil, domIdentifier: String? = nil,
        domClasses: [String] = [], frame: CGRect = .zero, pid: Int32 = 0,
        bundleID: String, windowTitle: String? = nil, url: URL? = nil
    ) {
        self.role = role
        self.subrole = subrole
        self.title = title
        self.placeholder = placeholder
        self.label = label
        self.domIdentifier = domIdentifier
        self.domClasses = domClasses
        self.frame = frame
        self.pid = pid
        self.bundleID = bundleID
        self.windowTitle = windowTitle
        self.url = url
    }

    private enum CodingKeys: String, CodingKey {
        case role, subrole, title, placeholder, label, domIdentifier, domClasses
        case frame, pid, bundleID, windowTitle, url
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        role = try c.decodeIfPresent(String.self, forKey: .role)
        subrole = try c.decodeIfPresent(String.self, forKey: .subrole)
        title = try c.decodeIfPresent(String.self, forKey: .title)
        placeholder = try c.decodeIfPresent(String.self, forKey: .placeholder)
        label = try c.decodeIfPresent(String.self, forKey: .label)
        domIdentifier = try c.decodeIfPresent(String.self, forKey: .domIdentifier)
        domClasses = try c.decodeIfPresent([String].self, forKey: .domClasses) ?? []
        frame = try c.decodeIfPresent(CGRect.self, forKey: .frame) ?? .zero
        pid = try c.decodeIfPresent(Int32.self, forKey: .pid) ?? 0
        bundleID = try c.decode(String.self, forKey: .bundleID)
        windowTitle = try c.decodeIfPresent(String.self, forKey: .windowTitle)
        url = try c.decodeIfPresent(URL.self, forKey: .url)
    }
}
