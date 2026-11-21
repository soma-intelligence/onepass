package me.somalabs.onepass.screens

import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.RadioButton
import me.somalabs.onepass.MainActivity
import me.somalabs.onepass.R
import me.somalabs.onepass.core.FfiDuplicateAspect
import me.somalabs.onepass.core.FfiDuplicateChoice
import me.somalabs.onepass.core.FfiDuplicateConfidence
import me.somalabs.onepass.core.FfiDuplicateCopy
import me.somalabs.onepass.core.FfiDuplicateGroup
import me.somalabs.onepass.core.FfiDuplicateRowKind
import me.somalabs.onepass.core.FfiDuplicateSignal
import me.somalabs.onepass.core.FfiItemKey
import me.somalabs.onepass.ui.Ios

/**
 * "Doublons possibles" (iPhone: DuplicatesReviewView): the groups the core
 * finds (`duplicate_groups`). "Fusion sûre" merges the ticked groups at once
 * (`merge_sure_duplicates`); "À vérifier" shows each conflicting value per
 * copy, the user picks the right one and merges (`merge_duplicates_with`), or
 * says they are not duplicates, or archives / deletes the other copies.
 * Nothing is lost: merged copies are archived intact.
 */
class DuplicatesScreen(private val a: MainActivity) {
    private val ui get() = a.ui

    fun open() {
        val s = a.session() ?: return
        a.background({ s.duplicateGroups(emptyList()) }) { r ->
            r.onSuccess { groups -> a.push { page(groups) } }.onFailure { a.toast(a.message(it)) }
        }
    }

    private fun refresh() {
        val s = a.session() ?: return
        a.background({ s.duplicateGroups(emptyList()) }) { r ->
            a.changed {
                a.popNow()
                r.onSuccess { groups -> a.push { page(groups) } }
            }
        }
    }

    private fun reason(g: FfiDuplicateGroup): String = when (g.signals.firstOrNull()) {
        FfiDuplicateSignal.SAME_TOTP -> a.t("Même code de vérification", "Same verification code")
        FfiDuplicateSignal.SAME_CARD_NUMBER -> a.t("Même numéro de carte", "Same card number")
        FfiDuplicateSignal.SAME_DOCUMENT_NUMBER -> a.t("Même numéro de document", "Same document number")
        FfiDuplicateSignal.SAME_LOGIN -> g.domain?.let { a.t("Même identifiant sur $it", "Same username on $it") } ?: a.t("Même titre et même identifiant", "Same title and username")
        else -> a.t("Même titre et même identifiant", "Same title and username")
    }

    private fun aspect(x: FfiDuplicateAspect) = when (x) {
        FfiDuplicateAspect.TITLE -> a.t("titre", "title")
        FfiDuplicateAspect.USERNAME -> a.t("identifiant", "username")
        FfiDuplicateAspect.PASSWORD -> a.t("mot de passe", "password")
        FfiDuplicateAspect.WEBSITES -> a.t("sites", "websites")
        FfiDuplicateAspect.TOTP -> a.t("code de vérification", "verification code")
        FfiDuplicateAspect.PASSKEYS -> "passkeys"
        FfiDuplicateAspect.NOTES -> "notes"
        FfiDuplicateAspect.FIELDS -> a.t("champs", "fields")
        FfiDuplicateAspect.ATTACHMENTS -> a.t("pièces jointes", "attachments")
        FfiDuplicateAspect.TAGS -> "tags"
    }

    private fun copyLine(c: FfiDuplicateCopy) = if (c.differences.isEmpty()) a.t("Identique", "Identical")
    else a.t("Diffère : ", "Differs: ") + c.differences.joinToString(", ") { aspect(it) }

    private fun key(c: FfiDuplicateCopy) = FfiItemKey(c.summary.vaultId, c.summary.id)

    private fun note(title: String) = a.t("Fusionné dans « $title »", "Merged into “$title”")

    private fun page(groups: List<FfiDuplicateGroup>): View {
        val sure = groups.filter { it.confidence == FfiDuplicateConfidence.SURE }
        val review = groups.filter { it.confidence == FfiDuplicateConfidence.REVIEW }
        return a.pushedPage(a.t("Doublons possibles", "Possible Duplicates"), largeTitle = true) {
            if (groups.isEmpty()) {
                addView(ui.inset(ui.card(LinearLayout(a).apply {
                    orientation = LinearLayout.VERTICAL
                    gravity = Gravity.CENTER_HORIZONTAL
                    setPadding(ui.dp(16), ui.dp(24), ui.dp(16), ui.dp(24))
                    addView(ui.glyph(R.drawable.ic_check_circle, ui.green, 40))
                    addView(ui.text(a.t("Aucun doublon", "No Duplicates"), 17f, ui.label, 600).apply { setPadding(0, ui.dp(10), 0, ui.dp(4)) })
                    addView(ui.text(a.t("Les éléments qui se ressemblent beaucoup apparaîtront ici.", "Items that look very much alike show up here."), 15f, ui.secondary).apply { gravity = Gravity.CENTER })
                }), top = Ios.Space.S))
                return@pushedPage
            }
            addView(ui.footnote(a.t("Sans risque : ${sure.size} · À vérifier : ${review.size}", "Safe to merge: ${sure.size} · To check: ${review.size}")))
            if (sure.isNotEmpty()) sureSection(this, sure)
            if (review.isNotEmpty()) {
                addView(ui.sectionHeader(a.t("À vérifier", "To Check")))
                addView(ui.footnote(a.t("Les copies se contredisent. Choisis la bonne valeur pour chaque différence.", "The copies disagree. Pick the right value for each difference.")))
                review.forEach { addView(ui.inset(reviewCard(it), top = Ios.Space.M)) }
                addView(ui.footnote(a.t("Rien n'est perdu : l'autre mot de passe passe dans l'historique, les autres copies sont archivées intactes.",
                    "Nothing is lost: the other password goes to the history, the other copies are archived intact.")))
            }
        }
    }

    private fun groupHead(g: FfiDuplicateGroup): View = LinearLayout(a).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(ui.dp(16), ui.dp(12), ui.dp(16), ui.dp(4))
        addView(ui.text(g.copies.firstOrNull()?.summary?.title?.ifBlank { a.t("Sans titre", "Untitled") } ?: "", 17f, ui.label, 600))
        addView(ui.text(reason(g) + " · " + a.t("${g.copies.size} copies", "${g.copies.size} copies"), 13f, ui.secondary).apply { setPadding(0, ui.dp(2), 0, 0) })
    }

    private fun copyRow(c: FfiDuplicateCopy): View = ui.row(icon = a.itemIcon(c.summary.itemType, 30), title = c.vaultName + (c.summary.subtitle.takeIf { it.isNotBlank() }?.let { " · $it" } ?: ""),
        subtitle = copyLine(c), chevron = true) { a.items.detail(c.summary.vaultId, c.summary.id) }

    // ---- sure ---------------------------------------------------------------------------------------

    private fun sureSection(col: LinearLayout, sure: List<FfiDuplicateGroup>) {
        val ticked = sure.map { it.id }.toMutableSet()
        col.addView(ui.sectionHeader(a.t("Fusion sûre", "Safe to Merge")))
        col.addView(ui.footnote(a.t("Même élément : une copie ajoute seulement des infos. La fusion les garde toutes.", "Same item: one copy only adds details. The merge keeps them all.")))
        lateinit var button: android.widget.TextView
        fun label() = a.t("Fusionner la sélection (${ticked.size})", "Merge Selected (${ticked.size})")
        sure.forEach { g ->
            val box = CheckBox(a).apply {
                isChecked = true
                buttonTintList = android.content.res.ColorStateList.valueOf(ui.accent)
                contentDescription = a.t("Inclure dans la fusion", "Include in Merge")
                setOnCheckedChangeListener { _, on -> if (on) ticked.add(g.id) else ticked.remove(g.id); button.text = label(); button.alpha = if (ticked.isEmpty()) 0.45f else 1f }
            }
            val head = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL }
            head.addView(groupHead(g), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            head.addView(box)
            col.addView(ui.inset(ui.card(head, *g.copies.map { copyRow(it) }.toTypedArray()), top = Ios.Space.M))
        }
        button = ui.capsule(label()) {
            if (ticked.isEmpty()) return@capsule
            val s = a.session() ?: return@capsule
            a.background({ s.mergeSureDuplicates(ticked.toList(), emptyList(), a.t("Fusionné dans « {title} »", "Merged into “{title}”")) }) { r ->
                r.onSuccess { a.toast(a.t("${it.size} groupes fusionnés", "${it.size} groups merged")); refresh() }.onFailure { a.toast(a.message(it)) }
            }
        }
        col.addView(button, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { setMargins(ui.dp(16), ui.dp(16), ui.dp(16), 0) })
    }

    // ---- review -------------------------------------------------------------------------------------

    private fun reviewCard(g: FfiDuplicateGroup): View {
        val primary = g.copies.first()
        val answers = mutableMapOf<String, String?>()
        val rows = mutableListOf<View>(groupHead(g))
        g.copies.forEach { rows += copyRow(it) }
        g.rows.filter { it.kind == FfiDuplicateRowKind.CONFLICT }.forEach { row ->
            val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(ui.dp(16), ui.dp(10), ui.dp(16), ui.dp(10)) }
            col.addView(ui.text(row.label.ifBlank { aspect(row.aspect) }, 13f, ui.readableAccent, 500))
            val radios = mutableListOf<RadioButton>()
            row.values.forEachIndexed { i, v ->
                val copy = g.copies.getOrNull(i) ?: return@forEachIndexed
                val shown = v?.let { a.items.display(it) } ?: a.t("Aucune valeur", "No value")
                var revealed = !row.concealed
                val rb = RadioButton(a).apply {
                    text = (if (revealed) shown else "••••••••") + "  —  " + copy.vaultName
                    setTextColor(ui.label)
                    buttonTintList = android.content.res.ColorStateList.valueOf(ui.accent)
                    isChecked = (row.winner?.toInt() ?: 0) == i
                    setOnClickListener {
                        radios.forEach { r -> r.isChecked = r === this }
                        answers[row.subject] = copy.summary.id
                    }
                    if (row.concealed && v != null) setOnLongClickListener {
                        revealed = !revealed
                        text = (if (revealed) shown else "••••••••") + "  —  " + copy.vaultName
                        true
                    }
                }
                radios += rb
                col.addView(rb)
            }
            if (row.concealed) col.addView(ui.text(a.t("Appui long pour afficher", "Long press to show"), 12f, ui.tertiary))
            rows += col
        }
        val buttons = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(ui.dp(16), ui.dp(8), ui.dp(16), ui.dp(14)) }
        val s = a.vault.session
        buttons.addView(ui.capsule(a.t("Fusionner avec ces choix", "Merge with These Choices")) {
            s ?: return@capsule
            val choices = answers.map { (subject, from) -> FfiDuplicateChoice(subject, from) }
            a.background({ s.mergeDuplicatesWith(key(primary), g.copies.drop(1).map(::key), choices, note(primary.summary.title)) }) { r ->
                r.onSuccess { refresh() }.onFailure { a.toast(a.message(it)) }
            }
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        val line = LinearLayout(a).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(0, ui.dp(8), 0, 0) }
        line.addView(ui.capsule(a.t("Ce ne sont pas des doublons", "These Aren't Duplicates"), prominent = false) {
            s ?: return@capsule
            a.background({ s.dismissDuplicates(g.copies.map(::key)) }) { r -> r.onSuccess { refresh() }.onFailure { a.toast(a.message(it)) } }
        }.apply { textSize = 15f }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        val more = a.barIcon(R.drawable.ic_more_circle, a.t("Plus d'actions", "More Actions")) { v ->
            val del = a.t("Supprimer les autres", "Delete Others")
            a.menu(v, listOf(
                Triple(R.drawable.ic_archive, a.t("Archiver les autres", "Archive Others")) {
                    s?.let { ss -> a.background({ ss.archiveDuplicates(g.copies.drop(1).map(::key)) }) { r -> r.onSuccess { refresh() }.onFailure { a.toast(a.message(it)) } } }
                },
                Triple(R.drawable.ic_trash, del) {
                    a.confirm(a.t("Supprimer les autres copies ? Elles vont dans Supprimés récemment, d'où tu peux les restaurer.", "Delete the other copies? They go to Recently Deleted, where you can restore them."), del) {
                        s?.let { ss -> a.background({ ss.trashDuplicates(g.copies.drop(1).map(::key)) }) { r -> r.onSuccess { refresh() }.onFailure { a.toast(a.message(it)) } } }
                    }
                },
            ), setOf(del))
        }
        line.addView(more)
        buttons.addView(line)
        rows += buttons
        return ui.card(*rows.toTypedArray())
    }
}
