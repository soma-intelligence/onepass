import SwiftUI
import VaultKit
#if os(macOS)
import AppKit
#endif

/// Réglages > Organisation. A personal or business account: the ways in ("Join an organisation",
/// and "Create an organisation" on a Mac or an iPad). A managed account: its organisation as this
/// device pinned it (`OrgSession.phase`), and on a console device the native console v0: members,
/// join requests, invitations and the DNS record. An iPhone reads it only.
struct OrganisationSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if let org = model.shownOrgSession {
                OrgPage(org: org, settings: model.session.environment.settings)
            } else {
                OrgEntryPage()
            }
        }
        .settingsPage("org.title")
    }
}

/// No managed account shown: join one by link, or create one (console devices only).
private struct OrgEntryPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Form {
            Section {
                Button {
                    Task { await model.presentOrgSheet(.join(nil, nil)) }
                } label: {
                    Label("org.join.title", systemImage: "envelope.open")
                }
                .accessibilityIdentifier("org.entry.join")
                if OrgConsole.isConsoleDevice {
                    Button {
                        Task { await model.presentOrgSheet(.create(nil)) }
                    } label: {
                        Label("org.create.title", systemImage: "building.2")
                    }
                    .accessibilityIdentifier("org.entry.create")
                }
            } footer: {
                Text("org.entry.footer")
            }
        }
    }
}

/// The organisation of the managed account shown, by phase.
private struct OrgPage: View {
    let org: OrgSession
    let settings: VaultSettings

    @Environment(AppModel.self) private var model
    @State private var filter: MemberFilter = .all
    @State private var inviting = false
    @State private var request: FfiJoinRequest?
    @State private var sendingJoin = false
    @State private var verifying = false
    @State private var actionError: String?
    /// Bumped after a change of the slot's settings (they are not observable).
    @State private var settingsTick = 0

    enum MemberFilter: Hashable, CaseIterable {
        case all, active, suspended, removed

        var title: LocalizedStringKey {
            switch self {
            case .all: "org.filter.all"
            case .active: "org.state.active"
            case .suspended: "org.state.suspended"
            case .removed: "org.state.removed"
            }
        }

        func keeps(_ state: FfiMemberState) -> Bool {
            switch (self, state) {
            case (.all, _), (.active, .active), (.suspended, .suspended), (.removed, .removed): true
            default: false
            }
        }
    }

    /// A joiner whose request is not accepted yet (an account that created its org is never one).
    private var joining: Bool {
        guard !settings.orgCreator else { return false }
        return org.me == nil || org.me?.state == .invited
    }

    private var console: Bool { OrgConsole.isConsoleDevice }

    var body: some View {
        let _ = settingsTick
        Form {
            if settings.orgMemberTokenRefused, !settings.orgCreator {
                tokenRefused
            } else {
                switch org.phase {
                case .loading:
                    Section {
                        ProgressView().frame(maxWidth: .infinity)
                    }
                case .unavailable:
                    unavailable
                case .notJoined:
                    joinStatus
                case .unfinishedCreation:
                    unfinished
                case .refused(let refusal):
                    Section {
                        Label(refusal.message, systemImage: "exclamationmark.octagon")
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("org.refused")
                    }
                case .ready:
                    if joining { joinStatus } else { ready }
                }
            }
        }
        .task { await refresh() }
        .refreshable { await refresh() }
        .sheet(isPresented: $inviting) { OrgInviteSheet(org: org, settings: settings) }
        .sheet(item: $request) { OrgJoinRequestSheet(org: org, request: $0) }
        .sheet(isPresented: $sendingJoin, onDismiss: { settingsTick += 1 }) {
            PasswordPromptSheet(title: "org.join.send", footer: "settings.confirmWithMasterPassword") { password in
                do {
                    try await model.sendJoinRequest(slot: model.accounts.activeSlot, password: password)
                } catch {
                    throw VaultError.other(OrgActionError(error).message)
                }
            }
        }
    }

    private func refresh() async {
        if case .loading = org.phase {
            await org.load()
        } else if case .unavailable = org.phase {
            await org.load()
        } else {
            await org.refresh()
        }
        settingsTick += 1
    }

    // MARK: - Phases

    private var unavailable: some View {
        Section {
            Label(org.refreshError?.message ?? String(localized: "org.unavailable"), systemImage: "wifi.slash")
                .accessibilityIdentifier("org.unavailable")
            Button("org.action.retry") { Task { await org.load() } }
                .accessibilityIdentifier("org.retry")
        }
    }

    private var unfinished: some View {
        Section {
            Text("org.unfinished")
                .accessibilityIdentifier("org.unfinished")
            NavigationLink {
                SettingsPage.accounts.content
            } label: {
                Label("org.openAccounts", systemImage: "person.2")
            }
            .accessibilityIdentifier("org.openAccounts")
        }
    }

    /// R36: a spent or refused member token. Only a new link helps: no retry here.
    private var tokenRefused: some View {
        Section {
            Label("org.join.tokenRefused", systemImage: "link.badge.plus")
                .foregroundStyle(.orange)
                .accessibilityIdentifier("org.join.tokenRefused")
            NavigationLink {
                SettingsPage.accounts.content
            } label: {
                Label("org.openAccounts", systemImage: "person.2")
            }
            .accessibilityIdentifier("org.openAccounts")
        }
    }

    /// A joiner before acceptance: send the request when it still waits for presence (R34), else the
    /// join code to read out and the wait.
    @ViewBuilder private var joinStatus: some View {
        if let state = org.state {
            Section {
                Text(state.name).font(.title3.weight(.semibold))
            }
        }
        if !settings.orgJoinPosted {
            Section {
                Button {
                    sendingJoin = true
                } label: {
                    Label("org.join.send", systemImage: "paperplane")
                }
                .accessibilityIdentifier("org.join.send")
            } footer: {
                Text("org.join.sendFooter")
            }
        } else {
            Section {
                if let code = settings.orgJoinCode {
                    OrgCodeWords(words: code)
                        .font(.largeTitle)
                        .accessibilityIdentifier("org.join.code")
                }
            } header: {
                Text("org.join.readCode")
            }
            Section {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("org.join.waiting")
                }
                .accessibilityIdentifier("org.join.waiting")
            } footer: {
                if let error = org.refreshError { Text(error.message) }
            }
        }
    }

    // MARK: - Ready

    @ViewBuilder private var ready: some View {
        if let state = org.state {
            header(state)
            members(state)
            if console, org.canManageMembers {
                if !org.joinRequests.isEmpty { joinRequests }
                Section {
                    Button {
                        inviting = true
                    } label: {
                        Label("org.invite", systemImage: "person.badge.plus")
                    }
                    .accessibilityIdentifier("org.invite")
                }
                #if os(macOS)
                if !org.myRoles.isDisjoint(with: [.owner, .admin]) { dnsRecord(state) }
                #endif
            }
        }
    }

    @ViewBuilder private func header(_ state: FfiOrgState) -> some View {
        Section {
            Text(state.name)
                .font(.title3.weight(.semibold))
                .accessibilityIdentifier("org.name")
            OrgFingerprintView(words: state.fingerprintWords, source: state.source, domain: settings.orgDomain)
            if org.needsVerification {
                Text("org.tofu.warning")
                    .font(.footnote)
                    .accessibilityIdentifier("org.tofu.warning")
                Button {
                    Task { await markVerified() }
                } label: {
                    Label("org.tofu.markVerified", systemImage: "checkmark.seal")
                }
                .disabled(verifying)
                .accessibilityIdentifier("org.tofu.markVerified")
            }
        } footer: {
            if let actionError {
                Text(actionError).foregroundStyle(.red)
            } else if let error = org.refreshError {
                Text(error.message)
            }
        }
    }

    @ViewBuilder private func members(_ state: FfiOrgState) -> some View {
        Section {
            Picker("org.filter", selection: $filter) {
                ForEach(MemberFilter.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityIdentifier("org.members.filter")
            ForEach(state.members.filter { filter.keeps($0.state) }, id: \.accountId) { member in
                NavigationLink {
                    OrgMemberDetailView(org: org, accountID: member.accountId)
                } label: {
                    OrgMemberRow(member: member, isMe: member.accountId == org.me?.accountId)
                }
            }
        } header: {
            Text("org.members")
        } footer: {
            if !console { Text("org.console.elsewhere") }
        }
    }

    private var joinRequests: some View {
        Section {
            ForEach(org.joinRequests, id: \.accountId) { item in
                Button {
                    request = item
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(item.displayName).font(.body.weight(.medium)).foregroundStyle(.primary)
                        Text(item.codeWords.joined(separator: " "))
                            .font(.callout.monospaced())
                            .foregroundStyle(.primary)
                        OrgRequestOrigin(request: item)
                    }
                    .padding(.vertical, 2)
                }
                .accessibilityIdentifier("org.request.\(item.accountId)")
            }
        } header: {
            Text("org.joinRequests")
        } footer: {
            Text("org.request.code")
        }
    }

    #if os(macOS)
    /// `_onepass.<domain>` TXT `v=op1; org=...`: lets new members' devices confirm the org by DNS.
    private func dnsRecord(_ state: FfiOrgState) -> some View {
        Section {
            DisclosureGroup("org.dns.title") {
                if let domain = settings.orgDomain {
                    LabeledContent("org.dns.name") {
                        Text(verbatim: "_onepass.\(domain)").font(.callout.monospaced()).textSelection(.enabled)
                    }
                }
                LabeledContent("org.dns.type") { Text(verbatim: "TXT").font(.callout.monospaced()) }
                LabeledContent("org.dns.value") {
                    Text(state.dnsValue).font(.callout.monospaced()).textSelection(.enabled)
                }
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(state.dnsValue, forType: .string)
                    model.showToast(String(localized: "common.copied"))
                } label: {
                    Label("common.copy", systemImage: "doc.on.doc")
                }
                .accessibilityIdentifier("org.dns.copy")
            }
            .accessibilityIdentifier("org.dns")
        } footer: {
            Text("org.dns.footer")
        }
    }
    #endif

    private func markVerified() async {
        verifying = true
        defer { verifying = false }
        do {
            try await org.markVerified()
            actionError = nil
        } catch {
            actionError = OrgActionError(error).message
        }
    }
}
