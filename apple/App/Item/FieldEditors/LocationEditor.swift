import CoreLocation
import DesignKit
import MapKit
import SwiftUI
import VaultKit

/// Location: label, address (typed with Apple's suggestions, or "Utiliser ma position"), a small
/// map with the pin, then the coordinates and the radius for fine tuning.
///
/// Privacy: the coordinates stay on the device. The only things sent anywhere are what the user
/// types in "Adresse" (to Apple, for the suggestions and the geocoding) and, once a place is set,
/// the map area MapKit draws. "Utiliser ma position" stores the coordinates only: no reverse
/// geocoding, so the position itself is never sent to a geocoder.
struct LocationEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue
    @State private var completer = AddressCompleter()
    @State private var addressText = ""
    @State private var status: Status = .idle
    @FocusState private var addressFocused: Bool

    private static let blank = FfiLocation(label: "", address: nil, lat: 0, lon: 0, radiusM: 100, suggestNearby: false)

    enum Status: Equatable {
        case idle, searching, locating, notFound, denied, unavailable
    }

    private var location: FfiLocation {
        if case .location(let l) = value { l } else { Self.blank }
    }

    private var point: GeoPoint { GeoPoint(latitude: location.lat, longitude: location.lon) }

    private func update(_ change: (inout FfiLocation) -> Void) {
        var l = location
        change(&l)
        value = l == Self.blank ? .empty : .location(value: l)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("Étiquette", text: Binding(get: { location.label }, set: { t in update { $0.label = t } }))
                .accessibilityIdentifier("editor.field.\(field.id)")
            addressField
            if addressFocused, !completer.results.isEmpty { suggestions }
            HStack(spacing: 12) {
                Button {
                    Task { await useCurrentLocation() }
                } label: {
                    Label("Utiliser ma position", systemImage: "location.fill")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(Theme.readableAccent)
                }
                .buttonStyle(.borderless)
                .disabled(status == .locating)
                .accessibilityIdentifier("editor.location.useCurrent")
                statusView
                Spacer(minLength: 0)
            }
            if point.isPlaced {
                LocationMap(point: point, title: location.label)
                    .frame(height: 120)
                    .accessibilityIdentifier("editor.location.map")
            }
            HStack {
                coordinate("Latitude", value: location.lat, range: -90...90) { v in update { $0.lat = v } }
                    .accessibilityIdentifier("editor.field.\(field.id).lat")
                coordinate("Longitude", value: location.lon, range: -180...180) { v in update { $0.lon = v } }
                    .accessibilityIdentifier("editor.field.\(field.id).lon")
            }
            .font(.callout)
            HStack {
                Text("Rayon (m)").foregroundStyle(.secondary)
                ParsedTextField(
                    title: String(localized: "Rayon"), prompt: "100", kind: .number,
                    value: Int64(location.radiusM),
                    parse: { NumberInput.integer($0).flatMap { (0...Int64(UInt32.max)).contains($0) ? $0 : nil } },
                    format: { String($0) },
                    commit: { v in update { $0.radiusM = UInt32(v ?? 0) } })
                    .multilineTextAlignment(.trailing)
            }
            .font(.callout)
        }
        .onAppear { addressText = location.address ?? "" }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("editor.location")
    }

    // MARK: - Address

    private var addressField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary).accessibilityHidden(true)
            TextField("Adresse", text: $addressText, prompt: Text("Cherche une adresse ou un lieu"))
                .focused($addressFocused)
                .onSubmit { Task { await geocodeTyped() } }
                .accessibilityIdentifier("editor.location.address")
            if status == .searching { ProgressView().controlSize(.small) }
        }
        .onChange(of: addressText) { _, text in
            update { $0.address = text.isEmpty ? nil : text }
            if addressFocused { completer.search(text) }
            if status == .notFound { status = .idle }
        }
        .onChange(of: addressFocused) { _, focused in
            if !focused { completer.clear() }
        }
    }

    private var suggestions: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(completer.results.enumerated()), id: \.offset) { index, completion in
                Button {
                    Task { await choose(completion) }
                } label: {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(completion.title).foregroundStyle(.primary)
                        if !completion.subtitle.isEmpty {
                            Text(completion.subtitle).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 6)
                    .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("editor.location.suggestion.\(index)")
                if index < completer.results.count - 1 { Divider() }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 2)
        .background(.fill.tertiary, in: .rect(cornerRadius: 9))
    }

    @ViewBuilder private var statusView: some View {
        switch status {
        case .idle, .searching:
            EmptyView()
        case .locating:
            ProgressView().controlSize(.small)
        case .notFound:
            Text("Adresse introuvable").font(.footnote).foregroundStyle(.secondary)
        case .unavailable:
            Text("Position introuvable").font(.footnote).foregroundStyle(.secondary)
        case .denied:
            HStack(spacing: 6) {
                Text("Position non autorisée").font(.footnote).foregroundStyle(.secondary)
                Button("Ouvrir les Réglages") { LocationAccess.openSettings() }
                    .font(.footnote)
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("editor.location.openSettings")
            }
        }
    }

    /// A suggestion: its place, its address, and its name as the label when none was typed.
    private func choose(_ completion: MKLocalSearchCompletion) async {
        addressFocused = false
        completer.clear()
        status = .searching
        let response = try? await MKLocalSearch(request: MKLocalSearch.Request(completion: completion)).start()
        guard let item = response?.mapItems.first else {
            status = .notFound
            return
        }
        let address = [completion.title, completion.subtitle].filter { !$0.isEmpty }.joined(separator: ", ")
        place(item, address: address)
        status = .idle
    }

    /// Return in "Adresse": the first place Apple finds for the text.
    private func geocodeTyped() async {
        let text = addressText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, let request = MKGeocodingRequest(addressString: text) else { return }
        completer.clear()
        status = .searching
        guard let item = (try? await request.mapItems)?.first else {
            status = .notFound
            return
        }
        place(item, address: nil)
        status = .idle
    }

    private func place(_ item: MKMapItem, address: String?) {
        let coordinate = item.location.coordinate
        let full = address ?? item.address.map { $0.fullAddress.replacingOccurrences(of: "\n", with: ", ") }
        update { l in
            l.lat = coordinate.latitude
            l.lon = coordinate.longitude
            if let full, !full.isEmpty { l.address = full }
            if l.label.isEmpty, let name = item.name, !name.isEmpty, name != full { l.label = name }
        }
        if let full, !full.isEmpty { addressText = full }
    }

    private func useCurrentLocation() async {
        status = .locating
        do {
            let here = try await LocationAccess.shared.currentLocation()
            update { l in
                l.lat = here.coordinate.latitude
                l.lon = here.coordinate.longitude
            }
            status = .idle
        } catch LocationAccess.Failure.denied {
            status = .denied
        } catch {
            status = .unavailable
        }
    }

    /// Latitude or longitude typed as text: minus sign, "," or "." accepted, parsed on every keystroke,
    /// out of range values refused.
    private func coordinate(
        _ title: String, value: Double, range: ClosedRange<Double>, commit: @escaping (Double) -> Void
    ) -> some View {
        ParsedTextField(
            title: title, prompt: "0,0", kind: .location, value: value,
            parse: { NumberInput.double($0).flatMap { range.contains($0) ? $0 : nil } },
            format: NumberInput.text,
            commit: { commit($0 ?? 0) })
    }

    /// "48.85661, 2.35222".
    static func coordinates(_ l: FfiLocation) -> String {
        String(format: "%.5f, %.5f", l.lat, l.lon)
    }
}

/// Apple's address suggestions for the text typed in "Adresse" (needs three characters). No search
/// region is set: the user's position is never given to the completer.
@MainActor
@Observable
final class AddressCompleter: NSObject, MKLocalSearchCompleterDelegate {
    private(set) var results: [MKLocalSearchCompletion] = []
    @ObservationIgnored private let completer = MKLocalSearchCompleter()
    @ObservationIgnored private let limit: Int

    init(limit: Int = 4) {
        self.limit = limit
        super.init()
        completer.delegate = self
        completer.resultTypes = [.address, .pointOfInterest]
    }

    func search(_ text: String) {
        let query = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard query.count >= 3 else { return clear() }
        completer.queryFragment = query
    }

    func clear() {
        completer.cancel()
        results = []
    }

    nonisolated func completerDidUpdateResults(_ completer: MKLocalSearchCompleter) {
        // Our own completer (the parameter is not sent across): read on the main actor.
        MainActor.assumeIsolated { results = Array(self.completer.results.prefix(limit)) }
    }

    nonisolated func completer(_ completer: MKLocalSearchCompleter, didFailWithError error: any Error) {
        MainActor.assumeIsolated { results = [] }
    }
}

/// A small still map with the place's pin (MapKit tiles only, no other map service).
struct LocationMap: View {
    let point: GeoPoint
    let title: String

    private var coordinate: CLLocationCoordinate2D {
        CLLocationCoordinate2D(latitude: point.latitude, longitude: point.longitude)
    }

    var body: some View {
        Map(
            initialPosition: .region(MKCoordinateRegion(center: coordinate, latitudinalMeters: 700, longitudinalMeters: 700)),
            interactionModes: []
        ) {
            Marker(title.isEmpty ? String(localized: "Lieu") : title, coordinate: coordinate)
        }
        .mapStyle(.standard(pointsOfInterest: .excludingAll))
        .mapControlVisibility(.hidden)
        // A new place re-centers the map (the initial position is read once).
        .id(point)
        .clipShape(.rect(cornerRadius: 10))
        .overlay { RoundedRectangle(cornerRadius: 10).strokeBorder(.white.opacity(0.08)) }
        .accessibilityLabel(Text("Carte de \(title.isEmpty ? String(localized: "ce lieu") : title)"))
    }
}

extension FfiLocation {
    /// "Ouvrir dans Plans": the place in Apple Plans (the user's own action).
    func openInMaps() {
        let item = MKMapItem(location: CLLocation(latitude: lat, longitude: lon), address: nil)
        if !label.isEmpty { item.name = label }
        _ = item.openInMaps(launchOptions: nil)
    }
}

// MARK: - Item places ("+ ajouter un lieu")

/// One place of an item, as a card block: the map (rounded, 160 pt, pin, still), then its label
/// and address, with an accessory on the right (remove in the editor, distance in the detail).
struct PlaceBlock<Accessory: View>: View {
    let location: FfiLocation
    @ViewBuilder var accessory: Accessory

    private var point: GeoPoint { GeoPoint(latitude: location.lat, longitude: location.lon) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if point.isPlaced {
                LocationMap(point: point, title: location.label).frame(height: 160)
            }
            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(location.label.isEmpty ? String(localized: "Lieu") : location.label)
                        .font(.body.weight(.semibold))
                    if let address = location.address, !address.isEmpty {
                        Text(address).font(.callout).foregroundStyle(.secondary).lineLimit(2)
                    } else if point.isPlaced {
                        Text(LocationEditor.coordinates(location)).font(.callout.monospaced()).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                accessory
            }
        }
        .editorRowPadding()
    }
}

/// Apple Plans style search for a place: the search field, "Utiliser ma position" on top, then
/// Apple's live suggestions (name and address, with a pin). Picking one hands back a place.
///
/// Privacy: the typed text goes to Apple for the suggestions; "Utiliser ma position" keeps the
/// coordinates on the device (no reverse geocoding).
struct LocationSearchSheet: View {
    let onPick: (FfiLocation) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var completer = AddressCompleter(limit: 8)
    @State private var query = ""
    @State private var status: LocationEditor.Status = .idle
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Ajouter un lieu").font(.headline)
                Spacer()
                Button("Annuler") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("location.search.cancel")
            }
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary).accessibilityHidden(true)
                TextField("Rechercher", text: $query, prompt: Text("Cherche un lieu ou une adresse"))
                    .textFieldStyle(.plain)
                    .focused($focused)
                    .onSubmit { Task { await geocodeTyped() } }
                    .accessibilityIdentifier("location.search.field")
                if status == .searching || status == .locating { ProgressView().controlSize(.small) }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(.fill.quaternary, in: .rect(cornerRadius: 10))
            .onChange(of: query) { _, text in
                completer.search(text)
                if status == .notFound { status = .idle }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    resultRow(
                        icon: "location.fill", tint: .blue, title: String(localized: "Utiliser ma position"),
                        subtitle: statusText, id: "location.search.current"
                    ) { Task { await useCurrentLocation() } }
                    if status == .denied {
                        Button("Ouvrir les Réglages") { LocationAccess.openSettings() }
                            .buttonStyle(.borderless)
                            .padding(.leading, 44)
                            .padding(.bottom, 6)
                            .accessibilityIdentifier("location.search.openSettings")
                    }
                    ForEach(Array(completer.results.enumerated()), id: \.offset) { index, completion in
                        Divider().padding(.leading, 44)
                        resultRow(
                            icon: "mappin", tint: .red, title: completion.title, subtitle: completion.subtitle,
                            id: "location.search.result.\(index)"
                        ) { Task { await choose(completion) } }
                    }
                }
            }
        }
        .padding(16)
        #if os(macOS)
        .frame(width: 440, height: 460)
        #endif
        .task { focused = true }
    }

    private var statusText: String {
        switch status {
        case .denied: String(localized: "Position non autorisée")
        case .unavailable: String(localized: "Position introuvable")
        case .notFound: String(localized: "Adresse introuvable")
        default: String(localized: "Elle reste sur cet appareil")
        }
    }

    private func resultRow(
        icon: String, tint: Color, title: String, subtitle: String, id: String, action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(width: 30, height: 30)
                    .background(tint, in: Circle())
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).foregroundStyle(.primary).lineLimit(1)
                    if !subtitle.isEmpty {
                        Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 7)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(id)
    }

    private func pick(_ location: FfiLocation) {
        onPick(location)
        dismiss()
    }

    private func choose(_ completion: MKLocalSearchCompletion) async {
        status = .searching
        let response = try? await MKLocalSearch(request: MKLocalSearch.Request(completion: completion)).start()
        guard let item = response?.mapItems.first else {
            status = .notFound
            return
        }
        let coordinate = item.location.coordinate
        pick(FfiLocation(
            label: completion.title,
            address: completion.subtitle.isEmpty ? nil : completion.subtitle,
            lat: coordinate.latitude, lon: coordinate.longitude, radiusM: 100, suggestNearby: true))
    }

    private func geocodeTyped() async {
        let text = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, let request = MKGeocodingRequest(addressString: text) else { return }
        status = .searching
        guard let item = (try? await request.mapItems)?.first else {
            status = .notFound
            return
        }
        let coordinate = item.location.coordinate
        let address = item.address.map { $0.fullAddress.replacingOccurrences(of: "\n", with: ", ") } ?? text
        pick(FfiLocation(
            label: item.name ?? text, address: address,
            lat: coordinate.latitude, lon: coordinate.longitude, radiusM: 100, suggestNearby: true))
    }

    private func useCurrentLocation() async {
        status = .locating
        do {
            let here = try await LocationAccess.shared.currentLocation()
            pick(FfiLocation(
                label: String(localized: "Ma position"), address: nil,
                lat: here.coordinate.latitude, lon: here.coordinate.longitude, radiusM: 100, suggestNearby: true))
        } catch LocationAccess.Failure.denied {
            status = .denied
        } catch {
            status = .unavailable
        }
    }
}
