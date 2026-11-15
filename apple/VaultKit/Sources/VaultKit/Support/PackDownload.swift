import Foundation

/// The two file steps shared by the signed packs (`IconPackStore`, `SitePackStore`): a bounded
/// HTTPS download and an atomic swap into the pack folder.
enum PackDownload {
    enum Failure: Error, Equatable {
        case notHTTPS
        case badResponse
        case tooLarge
    }

    /// HTTPS GET, 200 only, at most `limit` bytes (the declared length is checked first, the
    /// downloaded file after).
    static func get(_ url: URL, limit: Int, session: URLSession) async throws -> Data {
        guard url.scheme == "https" else { throw Failure.notHTTPS }
        let (file, response) = try await session.download(from: url)
        defer { try? FileManager.default.removeItem(at: file) }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw Failure.badResponse }
        guard http.expectedContentLength <= Int64(limit),
            let size = (try? FileManager.default.attributesOfItem(atPath: file.path())[.size]) as? Int, size <= limit
        else { throw Failure.tooLarge }
        return try Data(contentsOf: file)
    }

    /// Written beside its place, then renamed over it: a reader sees the old file or the new one.
    static func swapIn(_ data: Data, as name: String, in directory: URL) throws {
        let target = directory.appending(path: name)
        let temporary = directory.appending(path: ".\(name).\(UUID().uuidString)")
        do {
            try data.write(to: temporary, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            if FileManager.default.fileExists(atPath: target.path()) {
                _ = try FileManager.default.replaceItemAt(target, withItemAt: temporary)
            } else {
                try FileManager.default.moveItem(at: temporary, to: target)
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }
}
