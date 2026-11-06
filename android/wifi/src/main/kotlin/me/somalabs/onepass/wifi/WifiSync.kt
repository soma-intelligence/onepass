package me.somalabs.onepass.wifi

/** The two personal security types an Android suggestion can carry. */
enum class WifiSecurity { WPA2, WPA3 }

/** What Android keys a suggestion by: SSID and security type. */
data class NetworkKey(val ssid: String, val security: WifiSecurity)

/**
 * One network OnePass hands to Android, as the core chose it
 * (`Session.wifiNetworks`, shared model `onepass_core::wifi`: SSID plus a
 * WPA2 or WPA3 personal key, never open, WEP or enterprise, one per SSID).
 * [fingerprint] is secret free and moves when the item changes. The
 * passphrase never shows in logs.
 */
data class WifiNetwork(
    val ssid: String,
    val passphrase: String,
    val security: WifiSecurity,
    val hidden: Boolean,
    val itemId: String,
    val fingerprint: String,
) {
    val key: NetworkKey get() = NetworkKey(ssid, security)

    /**
     * A raw 256-bit key (64 hex digits) instead of a passphrase: Android
     * suggestions only take a passphrase (8 to 63 characters), so such a
     * network stays off the device rather than failing every sync.
     */
    val hasRawKey: Boolean
        get() = passphrase.length == 64 && passphrase.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    override fun toString(): String =
        "WifiNetwork(ssid=$ssid, security=$security, hidden=$hidden, itemId=$itemId, " +
            "fingerprint=$fingerprint, passphrase=[redacted])"
}

/** What OnePass gave Android for one SSID. No secret. */
data class Applied(val security: WifiSecurity, val fingerprint: String)

/** Android's answer about the one-time "allow suggested networks" prompt. */
enum class SuggestionApproval {
    /** Before Android 12 the app cannot ask. */
    UNKNOWN,
    PENDING,
    APPROVED,
    REJECTED,
}

/** What the platform said to an add or a remove. */
sealed interface PortResult {
    data object Ok : PortResult

    /** Android refused (status code of WifiManager, or an exception). Never carries a value. */
    data class Refused(val reason: String) : PortResult
}

/**
 * The slice of WifiManager OnePass uses, behind an interface so the sync logic
 * is tested on the JVM against a fake.
 */
interface SuggestionPort {
    /**
     * The SSIDs of the suggestions this app has installed, or null where the
     * platform cannot list them (Android 10).
     */
    fun installedSsids(): Set<String>?

    fun add(networks: List<WifiNetwork>): PortResult

    fun remove(keys: List<NetworkKey>): PortResult

    /** Removes every suggestion of this app. */
    fun removeAll(): PortResult

    /** Android 11 and later update a suggestion re-added under the same key; Android 10 refuses a duplicate. */
    val replacesInPlace: Boolean

    fun approval(): SuggestionApproval
}

/** What OnePass last installed, by SSID. Lives in app preferences. */
interface SyncLedger {
    fun read(): Map<String, Applied>

    fun write(entries: Map<String, Applied>)

    /** Whether the user was already told about the one-time approval. */
    var approvalNoticeShown: Boolean
}

/** The changes that bring the device to the vault. */
data class SyncPlan(
    val add: List<WifiNetwork>,
    /** Each changed network with what Android holds for its SSID now. */
    val update: List<Pair<WifiNetwork, Applied>>,
    val remove: List<NetworkKey>,
    /** The device lost suggestions the ledger lists: drop them all and install again. */
    val rebuild: Boolean,
) {
    val isEmpty: Boolean get() = add.isEmpty() && update.isEmpty() && remove.isEmpty() && !rebuild

    companion object {
        /**
         * [installedSsids] is what the platform reports (null when it cannot
         * list): an SSID the ledger lists but the platform lacks means the
         * suggestions were lost, and the plan rebuilds from scratch.
         */
        fun of(desired: List<WifiNetwork>, ledger: Map<String, Applied>, installedSsids: Set<String>?): SyncPlan {
            val lost = installedSsids != null && ledger.keys.any { it !in installedSsids }
            if (lost) return SyncPlan(add = desired, update = emptyList(), remove = emptyList(), rebuild = true)
            val desiredSsids = desired.map { it.ssid }.toSet()
            val add = desired.filter { it.ssid !in ledger }
            val update = desired.mapNotNull { n ->
                ledger[n.ssid]?.takeIf { it.fingerprint != n.fingerprint }?.let { n to it }
            }
            val remove = ledger.filterKeys { it !in desiredSsids }
                .map { (ssid, applied) -> NetworkKey(ssid, applied.security) }
                .sortedBy { it.ssid }
            return SyncPlan(add, update, remove, rebuild = false)
        }
    }
}

/** What a sync did, for the settings screen. Counts only, never a network. */
data class SyncReport(
    val enabled: Boolean,
    /** Networks Android now holds from OnePass. */
    val installed: Int,
    val added: Int,
    val updated: Int,
    val removed: Int,
    val approval: SuggestionApproval,
    /** True exactly once: the first sync that hands Android networks before the user approved. */
    val showApprovalNotice: Boolean,
    val failure: String? = null,
    /** Vault networks Android cannot take (raw 64 hex digit keys). */
    val unsupported: Int = 0,
)

/**
 * Keeps Android's network suggestions equal to the vault's Wi-Fi networks.
 *
 * Idempotent: a second sync with the same vault touches nothing. Called with
 * the vault's networks after each unlock and each change of the vault (save,
 * trash, restore, archive, remote commit, Travel Mode).
 */
class WifiAutoSync(
    private val port: SuggestionPort,
    private val ledger: SyncLedger,
) {
    @Synchronized
    fun sync(networks: List<WifiNetwork>, enabled: Boolean): SyncReport {
        if (!enabled) return disable()
        val (raw, usable) = networks.partition { it.hasRawKey }
        val known = ledger.read()
        val plan = SyncPlan.of(usable, known, port.installedSsids())
        val failure = apply(plan, known)
        val installed = ledger.read()
        val approval = port.approval()
        val notice = installed.isNotEmpty() &&
            approval != SuggestionApproval.APPROVED &&
            !ledger.approvalNoticeShown
        if (notice) ledger.approvalNoticeShown = true
        fun current(n: WifiNetwork) = installed[n.ssid]?.fingerprint == n.fingerprint
        return SyncReport(
            enabled = true,
            installed = installed.size,
            added = plan.add.count(::current),
            updated = plan.update.count { current(it.first) },
            removed = plan.remove.count { it.ssid !in installed },
            approval = approval,
            showApprovalNotice = notice,
            failure = failure,
            unsupported = raw.size,
        )
    }

    /** The switch is off: every OnePass suggestion leaves the device. */
    @Synchronized
    fun disable(): SyncReport {
        val known = ledger.read()
        var failure: String? = null
        if (known.isNotEmpty()) {
            when (val r = port.removeAll()) {
                PortResult.Ok -> ledger.write(emptyMap())
                is PortResult.Refused -> failure = r.reason
            }
        }
        return SyncReport(
            enabled = false,
            installed = ledger.read().size,
            added = 0,
            updated = 0,
            removed = if (failure == null) known.size else 0,
            approval = port.approval(),
            showApprovalNotice = false,
            failure = failure,
        )
    }

    /** Applies the plan, writing the ledger after each step Android took. */
    private fun apply(plan: SyncPlan, known: Map<String, Applied>): String? {
        val now = known.toMutableMap()
        var failure: String? = null
        fun fail(reason: String) {
            failure = failure ?: reason
        }

        if (plan.rebuild) {
            when (val r = port.removeAll()) {
                PortResult.Ok -> now.clear()
                is PortResult.Refused -> return r.reason
            }
            ledger.write(now)
        }

        if (plan.remove.isNotEmpty()) {
            when (val r = port.remove(plan.remove)) {
                PortResult.Ok -> plan.remove.forEach { now.remove(it.ssid) }
                is PortResult.Refused -> fail(r.reason)
            }
            ledger.write(now)
        }

        // A changed security is another Android key, and Android 10 refuses a
        // duplicate: in both cases the old copy goes first.
        val replaceFirst = plan.update.filter { (n, old) -> !port.replacesInPlace || old.security != n.security }
        if (replaceFirst.isNotEmpty()) {
            when (val r = port.remove(replaceFirst.map { (n, old) -> NetworkKey(n.ssid, old.security) })) {
                PortResult.Ok -> replaceFirst.forEach { now.remove(it.first.ssid) }
                is PortResult.Refused -> fail(r.reason)
            }
            ledger.write(now)
        }

        addEach(plan.update.map { it.first } + plan.add, now)?.let(::fail)
        return failure
    }

    /**
     * Adds in one call; when Android refuses the batch, one by one so a single
     * bad network does not keep the others off the device.
     */
    private fun addEach(networks: List<WifiNetwork>, now: MutableMap<String, Applied>): String? {
        if (networks.isEmpty()) return null
        fun record(n: WifiNetwork) {
            now[n.ssid] = Applied(n.security, n.fingerprint)
        }
        val batch = port.add(networks)
        if (batch == PortResult.Ok) {
            networks.forEach(::record)
            ledger.write(now)
            return null
        }
        val failure = (batch as PortResult.Refused).reason
        if (networks.size > 1) {
            var first: String? = null
            for (n in networks) {
                when (val r = port.add(listOf(n))) {
                    PortResult.Ok -> record(n)
                    is PortResult.Refused -> first = first ?: r.reason
                }
            }
            ledger.write(now)
            return first
        }
        ledger.write(now)
        return failure
    }
}
