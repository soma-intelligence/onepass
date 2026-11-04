package me.somalabs.onepass.wifi

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

    /** Android refused (status code of WifiManager, or an exception's message). */
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

    /** Adds the networks. Where [replacesInPlace] is true, re-adding a key updates it. */
    fun add(networks: List<WifiNetwork>): PortResult

    fun remove(keys: List<NetworkKey>): PortResult

    /** Removes every suggestion of this app. */
    fun removeAll(): PortResult

    /** Android 11 and later update a suggestion re-added under the same key; Android 10 refuses a duplicate. */
    val replacesInPlace: Boolean

    fun approval(): SuggestionApproval
}

/**
 * What OnePass last installed: one fingerprint per network key, never the
 * passphrase. Lives in app preferences.
 */
interface SyncLedger {
    fun read(): Map<NetworkKey, String>

    fun write(entries: Map<NetworkKey, String>)

    /** Whether the user was already told about the one-time approval. */
    var approvalNoticeShown: Boolean
}

/**
 * Turns a network into a short keyed digest (HMAC under a key the device
 * keeps), so a changed passphrase shows up without storing it, nor anything
 * an attacker could test guesses against off the device.
 */
fun interface Fingerprinter {
    fun fingerprint(network: WifiNetwork): String
}

/** The changes that bring the device to the vault. */
data class SyncPlan(
    val add: List<WifiNetwork>,
    val update: List<WifiNetwork>,
    val remove: List<NetworkKey>,
    /** The device lost suggestions the ledger lists: drop them all and install again. */
    val rebuild: Boolean,
) {
    val isEmpty: Boolean get() = add.isEmpty() && update.isEmpty() && remove.isEmpty() && !rebuild

    companion object {
        /**
         * [installedSsids] is what the platform reports (null when it cannot
         * list): an SSID the ledger lists but the platform lacks means the
         * suggestions were lost (app data cleared on another path, a system
         * reset), and the plan rebuilds from scratch.
         */
        fun of(
            desired: List<WifiNetwork>,
            ledger: Map<NetworkKey, String>,
            installedSsids: Set<String>?,
            fingerprinter: Fingerprinter,
        ): SyncPlan {
            val lost = installedSsids != null && ledger.keys.any { it.ssid !in installedSsids }
            if (lost) return SyncPlan(add = desired, update = emptyList(), remove = emptyList(), rebuild = true)
            val desiredKeys = desired.map { it.key }.toSet()
            val add = desired.filter { it.key !in ledger }
            val update = desired.filter { network ->
                val known = ledger[network.key]
                known != null && known != fingerprinter.fingerprint(network)
            }
            val remove = ledger.keys.filter { it !in desiredKeys }.sortedWith(compareBy({ it.ssid }, { it.security }))
            return SyncPlan(add, update, remove, rebuild = false)
        }
    }
}

/** What a sync did, for the settings screen. */
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
)

/**
 * Keeps Android's network suggestions equal to the vault's router items.
 *
 * Idempotent: a second sync with the same vault touches nothing. Called with
 * every router item after each unlock and each change of the vault (save,
 * trash, restore, archive, remote commit, Travel Mode).
 */
class WifiAutoSync(
    private val port: SuggestionPort,
    private val ledger: SyncLedger,
    private val fingerprinter: Fingerprinter,
) {
    @Synchronized
    fun sync(records: List<RouterRecord>, enabled: Boolean): SyncReport {
        if (!enabled) return disable()
        val desired = WifiSelection.select(records)
        val known = ledger.read()
        val plan = SyncPlan.of(desired, known, port.installedSsids(), fingerprinter)
        val failure = apply(plan, known)
        val installed = ledger.read()
        val approval = port.approval()
        val notice = installed.isNotEmpty() &&
            approval != SuggestionApproval.APPROVED &&
            !ledger.approvalNoticeShown
        if (notice) ledger.approvalNoticeShown = true
        return SyncReport(
            enabled = true,
            installed = installed.size,
            added = if (plan.rebuild) installed.size else plan.add.count { it.key in installed },
            updated = plan.update.count { it.key in installed },
            removed = plan.remove.count { it !in installed },
            approval = approval,
            showApprovalNotice = notice,
            failure = failure,
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

    /** Applies the plan, writing the ledger after each step that Android took. */
    private fun apply(plan: SyncPlan, known: Map<NetworkKey, String>): String? {
        val ledgerNow = known.toMutableMap()
        var failure: String? = null

        if (plan.rebuild) {
            when (val r = port.removeAll()) {
                PortResult.Ok -> ledgerNow.clear()
                is PortResult.Refused -> return r.reason.also { ledger.write(ledgerNow) }
            }
            ledger.write(ledgerNow)
        }

        if (plan.remove.isNotEmpty()) {
            when (val r = port.remove(plan.remove)) {
                PortResult.Ok -> plan.remove.forEach { ledgerNow.remove(it) }
                is PortResult.Refused -> failure = r.reason
            }
            ledger.write(ledgerNow)
        }

        if (plan.update.isNotEmpty()) {
            if (!port.replacesInPlace) {
                // Android 10: drop the old copy first, or the add is a duplicate.
                when (val r = port.remove(plan.update.map { it.key })) {
                    PortResult.Ok -> plan.update.forEach { ledgerNow.remove(it.key) }
                    is PortResult.Refused -> failure = failure ?: r.reason
                }
                ledger.write(ledgerNow)
            }
            addEach(plan.update, ledgerNow)?.let { failure = failure ?: it }
        }

        addEach(plan.add, ledgerNow)?.let { failure = failure ?: it }
        return failure
    }

    /**
     * Adds in one call; when Android refuses the batch, one by one so a single
     * bad network does not keep the others off the device.
     */
    private fun addEach(networks: List<WifiNetwork>, ledgerNow: MutableMap<NetworkKey, String>): String? {
        if (networks.isEmpty()) return null
        val batch = port.add(networks)
        if (batch == PortResult.Ok) {
            networks.forEach { ledgerNow[it.key] = fingerprinter.fingerprint(it) }
            ledger.write(ledgerNow)
            return null
        }
        var failure: String? = (batch as PortResult.Refused).reason
        if (networks.size > 1) {
            failure = null
            for (network in networks) {
                when (val r = port.add(listOf(network))) {
                    PortResult.Ok -> ledgerNow[network.key] = fingerprinter.fingerprint(network)
                    is PortResult.Refused -> failure = failure ?: r.reason
                }
            }
        }
        ledger.write(ledgerNow)
        return failure
    }
}
