package me.somalabs.onepass.screens

import android.view.View
import java.text.DateFormat
import java.util.Date
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiTravelItemPlan
import me.somalabs.onepass.core.FfiTravelPlanEntry
import me.somalabs.onepass.core.FfiTravelStatus
import me.somalabs.onepass.ui.Ios

/**
 * Réglages > Travel Mode, as on iPhone (TravelSettings): the status, which
 * personal vault stays or leaves the device ("Sûr en voyage", set on every
 * device), what leaves with them and what stays guarded (`travel_plan`,
 * `travel_item_plan`, `travel_status`).
 *
 * Turning it on is refused here: the vaults that leave come back through
 * sync (`begin_travel_exit` lets the sync fetch them, `finish_travel_exit`
 * checks them), and Android has no sync yet, so they could not return.
 */
class TravelScreen(private val a: MainActivity) {
    private val ui get() = a.ui

    fun open() {
        val s = a.session() ?: return
        a.background({ Triple(s.travelStatus(), s.travelPlan(), runCatching { s.travelItemPlan() }.getOrNull()) }) { r ->
            r.onSuccess { (status, plan, items) -> a.push { page(status, plan, items) } }.onFailure { a.toast(a.message(it)) }
        }
    }

    private fun reopen() {
        val s = a.session() ?: return
        a.background({ Triple(s.travelStatus(), s.travelPlan(), runCatching { s.travelItemPlan() }.getOrNull()) }) { r ->
            a.changed {
                a.popNow()
                r.onSuccess { (status, plan, items) -> a.push { page(status, plan, items) } }
            }
        }
    }

    private fun page(status: FfiTravelStatus, plan: List<FfiTravelPlanEntry>, items: FfiTravelItemPlan?): View =
        a.pushedPage("Travel Mode", largeTitle = true) {
            val df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
            val state = if (status.active) {
                val n = status.hiddenCount.toInt()
                val vaults = if (n == 1) a.t("1 coffre", "1 vault") else a.t("$n coffres", "$n vaults")
                status.enteredAt?.let { a.t("Depuis le ${df.format(Date(it * 1000))}, $vaults hors de cet appareil", "Since ${df.format(Date(it * 1000))}, $vaults off this device") }
                    ?: a.t("Travel Mode activé", "Travel Mode on")
            } else a.t("Travel Mode désactivé", "Travel Mode off")
            addView(ui.inset(ui.card(ui.row(icon = a.itemIconArt(R.drawable.settings_travel, 30), title = state, chevron = false)), top = Ios.Space.S))

            val leaving = plan.filter { it.leaves }.map { it.name }
            val parts = mutableListOf<String>()
            if (leaving.isNotEmpty()) parts += a.t("Ces coffres quittent cet appareil jusqu'à ton retour : ${leaving.joinToString(", ")}.", "These vaults leave this device until you come back: ${leaving.joinToString(", ")}.")
            items?.hidden?.size?.takeIf { it > 0 }?.let { parts += a.t("$it éléments cachés partent aussi.", "$it hidden items leave too.") }
            items?.guarded?.size?.takeIf { it > 0 }?.let { parts += a.t("$it éléments restent, protégés par mot de passe maître et biométrie.", "$it items stay, protected by master password and biometrics.") }
            addView(ui.footnote(if (parts.isEmpty()) a.t("Rien ne quitterait cet appareil.", "Nothing would leave this device.") else parts.joinToString(" ")))

            addView(ui.inset(ui.card(ui.row(title = a.t("Activer le Travel Mode", "Turn On Travel Mode"), titleColor = ui.tertiary, chevron = false) {
                a.toast(a.t("Il faut d'abord la synchronisation sur Android.", "Android needs sync first."))
            }), top = Ios.Space.L))
            addView(ui.footnote(a.t("Les coffres retirés reviennent par la synchronisation, qui arrive sur Android : en attendant, le Travel Mode ne s'active pas sur cet appareil. Tu peux déjà choisir ce qui partirait.",
                "Removed vaults come back through sync, which is coming to Android: until then, Travel Mode does not turn on on this device. You can already choose what would leave.")))

            // Which vault stays.
            addView(ui.capsLabel(a.t("Sûr en voyage", "Safe for Travel")))
            addView(ui.inset(ui.card(*plan.map { e ->
                ui.toggleRow(e.name, if (e.leaves) a.t("Quitte l'appareil", "Leaves the device") else a.t("Reste sur l'appareil", "Stays on the device"), !e.leaves) { safe ->
                    val s = a.session() ?: return@toggleRow
                    val v = a.vaults.firstOrNull { it.id == e.vaultId } ?: return@toggleRow
                    a.background({ s.updateVault(v.id, v.meta.copy(travelSafe = safe)) }) { r -> r.onSuccess { reopen() }.onFailure { a.toast(a.message(it)) } }
                }
            }.toTypedArray())))
            addView(ui.footnote(a.t("Sur tous tes appareils.", "On all your devices.")))

            // Items set to leave or to be guarded.
            val listed = (items?.hidden.orEmpty().map { it to true } + items?.guarded.orEmpty().map { it to false })
            if (listed.isNotEmpty()) {
                addView(ui.capsLabel(a.t("Éléments", "Items")))
                addView(ui.inset(ui.card(*listed.map { (e, hidden) ->
                    ui.row(title = e.title.ifBlank { a.t("Sans titre", "Untitled") }, subtitle = e.vaultName + " · " + if (hidden) a.t("Caché en voyage", "Hidden in Travel Mode") else a.t("Protection renforcée en voyage", "Extra Protection in Travel Mode")) {
                        a.items.detail(e.vaultId, e.itemId)
                    }
                }.toTypedArray())))
            }
            addView(ui.footnote(a.t("Se règle dans chaque élément : Caché en voyage, ou Protection renforcée en voyage.", "Set in each item: Hidden in Travel Mode, or Extra Protection in Travel Mode.")))
        }
}
