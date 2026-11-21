import Foundation
import VaultKit

/// The CSCA master list shipped next to this file (csca-masterlist.ml, the BSI German Master List
/// of 1 October 2026), pinned by its SHA-256. The core cannot verify this list's signer (a
/// brainpoolP512r1 CSCA), so the app trusts exactly these bytes: a changed file fails the read.
/// To rotate it, follow csca-masterlist.README.md and replace `sha256` below (the one place the app
/// keeps it; core/onepass-core/tests/scan_master_list_bsi.rs checks the file against the same value).
enum CSCAMasterList {
    /// SHA-256 2bc0f28b35d83f2fc2d1495b1c715add358dfb9ba343e9788bc27a19ced13a9f.
    static let sha256 = Data([
        0x2B, 0xC0, 0xF2, 0x8B, 0x35, 0xD8, 0x3F, 0x2F,
        0xC2, 0xD1, 0x49, 0x5B, 0x1C, 0x71, 0x5A, 0xDD,
        0x35, 0x8D, 0xFB, 0x9B, 0xA3, 0x43, 0xE9, 0x78,
        0x8B, 0xC2, 0x7A, 0x19, 0xCE, 0xD1, 0x3A, 0x9F,
    ])

    /// The bytes of the bundled file, nil when the bundle lacks it.
    static func bundled(in bundle: Bundle = .main) -> Data? {
        guard let url = bundle.url(forResource: "csca-masterlist", withExtension: "ml") else { return nil }
        return try? Data(contentsOf: url, options: .mappedIfSafe)
    }

    /// A passport reader over `transport` that checks chips against the bundled list.
    static func reader(transport: any APDUTransport, bundle: Bundle = .main) -> PassportReader? {
        guard let bytes = bundled(in: bundle) else { return nil }
        return PassportReader(transport: transport, masterList: bytes, masterListSHA256: sha256)
    }
}
