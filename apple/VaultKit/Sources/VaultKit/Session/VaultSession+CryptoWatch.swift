import Foundation

extension VaultSession {
    /// The public watch data of every crypto wallet item (no network, no secret).
    public func watchWallets() async throws -> [FfiWalletWatch] {
        try await read { try $0.watchWallets() }
    }

    /// The account's encrypted watch file, once the account id is known.
    public var cryptoWatchStore: CryptoWatchStore? {
        guard let id = environment.settings.accountID, !id.isEmpty else { return nil }
        return CryptoWatchStore(environment: environment, accountID: id)
    }

    /// "Dériver les adresses publiques de cette phrase": the core reads the item's stored phrase in
    /// memory and returns public data only; this adds it to the item's `xpub` and
    /// `public_addresses` fields and saves. The phrase never reaches Swift for this.
    @discardableResult
    public func addDerivedWatchData(to item: FfiItem) async throws -> FfiItem {
        let (vaultID, itemID) = (item.vaultId, item.id)
        let derived = try await read { try $0.watchDerivePublic(vaultId: vaultID, itemId: itemID) }
        var updated = item
        updated.sections = CryptoWatchFields.merging(derived, into: item.sections)
        guard updated.sections != item.sections else { return item }
        return try await save(updated)
    }
}

/// Writing public watch data into a crypto wallet item's fields.
public enum CryptoWatchFields {
    public static let addressesField = "public_addresses"
    public static let xpubField = "xpub"

    /// The canonical entries already in `public_addresses`.
    static func entries(in sections: [FfiSection]) -> Set<String> {
        Set(sections.flatMap(\.fields).filter { $0.id == addressesField }
            .compactMap { try? watchParseEntry(text: $0.value.text).entry })
    }

    /// `sections` with the derived zpub in an empty `xpub` field (a different xpub the user typed is
    /// kept) and the Ethereum and Solana addresses added to `public_addresses` unless present.
    public static func merging(_ derived: FfiWalletPublic, into sections: [FfiSection]) -> [FfiSection] {
        var out = sections
        if let (s, f) = locate(xpubField, in: out), out[s].fields[f].value.text.trimmingCharacters(in: .whitespaces).isEmpty {
            out[s].fields[f].value = .text(value: derived.bitcoinZpub)
        }
        for (chain, address) in [(FfiWatchChain.ethereum, derived.ethereumAddress), (.solana, derived.solanaAddress)] {
            guard let entry = try? watchValidateAddress(chain: chain, text: address).entry,
                  !entries(in: out).contains(entry)
            else { continue }
            out = adding(entry, to: out)
        }
        return out
    }

    /// Adds one entry: into the first empty `public_addresses` field, else as a new copy after the
    /// last one.
    public static func adding(_ entry: String, to sections: [FfiSection]) -> [FfiSection] {
        var out = sections
        for s in out.indices {
            if let f = out[s].fields.firstIndex(where: { $0.id == addressesField && $0.value.text.isEmpty }) {
                out[s].fields[f].value = .text(value: entry)
                return out
            }
        }
        for s in out.indices {
            if let last = out[s].fields.lastIndex(where: { $0.id == addressesField }) {
                var copy = out[s].fields[last]
                copy.value = .text(value: entry)
                out[s].fields.insert(copy, at: last + 1)
                return out
            }
        }
        return out
    }

    static func locate(_ id: String, in sections: [FfiSection]) -> (Int, Int)? {
        for s in sections.indices {
            if let f = sections[s].fields.firstIndex(where: { $0.id == id }) { return (s, f) }
        }
        return nil
    }
}
