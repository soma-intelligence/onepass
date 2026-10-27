import Foundation
import Testing

@testable import VaultKit

/// Fictitious places around Paris (no real person's address).
private let hotelDeVille = GeoPoint(latitude: 48.85661, longitude: 2.35222)
/// About 350 m east of `hotelDeVille`.
private let nearHotelDeVille = GeoPoint(latitude: 48.85661, longitude: 2.35700)
/// La Défense, about 8.5 km away.
private let laDefense = GeoPoint(latitude: 48.89220, longitude: 2.23600)

private func location(_ p: GeoPoint, label: String = "Lieu") -> FfiLocation {
    FfiLocation(label: label, address: nil, lat: p.latitude, lon: p.longitude, radiusM: 100, suggestNearby: false)
}

@Suite("Location index (À proximité)")
struct LocationIndexTests {
    @Test func distanceIsHaversineInMeters() {
        #expect(LocationIndex.distance(hotelDeVille, hotelDeVille) == 0)
        let east = LocationIndex.distance(hotelDeVille, nearHotelDeVille)
        #expect(abs(east - 350) < 5)
        let defense = LocationIndex.distance(hotelDeVille, laDefense)
        #expect(abs(defense - 9_600) < 400)
        // Symmetric.
        #expect(abs(defense - LocationIndex.distance(laDefense, hotelDeVille)) < 0.001)
    }

    @Test func blankAndOutOfRangePointsAreNotPlaces() {
        #expect(!GeoPoint(latitude: 0, longitude: 0).isPlaced)
        #expect(!GeoPoint(latitude: 91, longitude: 2).isPlaced)
        #expect(!GeoPoint(latitude: 48, longitude: .nan).isPlaced)
        #expect(hotelDeVille.isPlaced)
    }

    @Test func nearbyKeepsItemsWithinRadiusClosestFirst() {
        let near = summary("Bureau", updatedAt: 1)
        let closest = summary("Boulangerie", updatedAt: 1)
        let far = summary("Tour", updatedAt: 1)
        let nowhere = summary("Note", updatedAt: 1)
        var index = LocationIndex()
        index.update(
            [
                near.id: .init(updatedAt: 1, points: [nearHotelDeVille]),
                closest.id: .init(updatedAt: 1, points: [laDefense, hotelDeVille]),
                far.id: .init(updatedAt: 1, points: [laDefense]),
                nowhere.id: .init(updatedAt: 1, points: []),
            ], keeping: [near, closest, far, nowhere])
        let result = index.nearby([near, closest, far, nowhere], from: hotelDeVille, within: LocationIndex.nearbyRadius)
        #expect(result.map(\.summary.title) == ["Boulangerie", "Bureau"])
        #expect(result[0].distance == 0)
        #expect(abs(result[1].distance - 350) < 5)
    }

    @Test func onlyNewOrModifiedItemsNeedLoading() {
        let a = summary("A", updatedAt: 10)
        let b = summary("B", updatedAt: 10)
        var index = LocationIndex()
        #expect(index.needsLoading([a, b]).count == 2)
        index.update([a.id: .init(updatedAt: 10, points: [hotelDeVille]), b.id: .init(updatedAt: 10, points: [])],
            keeping: [a, b])
        #expect(index.needsLoading([a, b]).isEmpty)
        var edited = a
        edited.updatedAt = 11
        #expect(index.needsLoading([edited, b]).map(\.id) == [a.id])
        // Read during the second of its last edit: read again (a same-second edit would be missed).
        index.update([a.id: .init(updatedAt: 10, points: [hotelDeVille], readAt: 10)], keeping: [a, b])
        #expect(index.needsLoading([a, b]).map(\.id) == [a.id])
        index.update([a.id: .init(updatedAt: 10, points: [hotelDeVille], readAt: 11)], keeping: [a, b])
        #expect(index.needsLoading([a, b]).isEmpty)
        // An item gone from the summaries leaves the index.
        index.update([:], keeping: [b])
        #expect(index.entries.keys.sorted() == [b.id])
    }

    @Test func distanceLabelsReadInFrench() {
        #expect(LocationIndex.distanceLabel(3) == "à 10 m")
        #expect(LocationIndex.distanceLabel(348) == "à 350 m")
        #expect(LocationIndex.distanceLabel(996) == "à 1 km")
        #expect(LocationIndex.distanceLabel(1_240) == "à 1,2 km")
        #expect(LocationIndex.distanceLabel(2_000) == "à 2 km")
    }

    @Test func pointsComeFromLocationFieldsAndItemLocations() throws {
        var item = FfiItem(
            id: "i", vaultId: "v", itemType: .secureNote, title: "Note", tags: [], favorite: false, color: nil,
            notes: "", urls: [], apps: [], locations: [location(laDefense)], loginMethods: [],
            sections: [
                FfiSection(id: "custom", label: "Autres", fields: [
                    FfiField(id: "custom_1", label: "Lieu", kind: .location, value: .location(value: location(hotelDeVille)),
                        required: false, repeatable: false, autofill: false),
                    FfiField(id: "custom_2", label: "Vide", kind: .location,
                        value: .location(value: location(GeoPoint(latitude: 0, longitude: 0))),
                        required: false, repeatable: false, autofill: false),
                ])
            ],
            expires: nil, rotateEveryDays: nil, reprompt: false, hideFromAutofill: false, watchtowerExclusions: [],
            onWatch: false, archived: false, trashedAt: nil, createdAt: 0, updatedAt: 0, passwordHistoryCount: 0,
            attachmentCount: 0)
        #expect(LocationIndex.points(of: item) == [hotelDeVille, laDefense])
        item.locations = []
        #expect(LocationIndex.points(of: item) == [hotelDeVille])
    }
}

@MainActor
@Suite("Session: À proximité", .serialized)
struct NearbySessionTests {
    @Test func customLocationFieldListsItemNearbyAndFollowsEdits() async throws {
        let harness = try SessionHarness()
        defer { harness.cleanUp() }
        let session = harness.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)

        var draft = ItemDraft(item: try session.newItem(type: .secureNote, vaultID: session.allVaults[0].id))
        draft.item.title = "Boulangerie"
        fillRequired(&draft.item)
        draft.addCustomField(kind: .location, label: "Lieu")
        let s = try #require(draft.item.sections.firstIndex { $0.id == ItemDraft.customSectionID })
        draft.setValue(.location(value: location(nearHotelDeVille)), sectionID: ItemDraft.customSectionID,
            fieldIndex: draft.item.sections[s].fields.count - 1)
        var saved = try await session.save(draft.item)
        try await addItem(session, title: "Sans lieu")

        var result = try await session.nearbyItems(from: hotelDeVille)
        #expect(result.map(\.summary.title) == ["Boulangerie"])

        // Moved to La Défense: the edit is read again, the item leaves "À proximité".
        let field = try #require(saved.sections.firstIndex { $0.id == ItemDraft.customSectionID })
        let last = saved.sections[field].fields.count - 1
        saved.sections[field].fields[last].value = .location(value: location(laDefense))
        saved = try await session.save(saved)
        result = try await session.nearbyItems(from: hotelDeVille)
        #expect(result.isEmpty)
        #expect(try await session.nearbyItems(from: laDefense).map(\.summary.id) == [saved.id])

        // Trashed items are never nearby.
        try await session.trash(itemID: saved.id, vaultID: saved.vaultId)
        #expect(try await session.nearbyItems(from: laDefense).isEmpty)

        session.lock()
    }
}
