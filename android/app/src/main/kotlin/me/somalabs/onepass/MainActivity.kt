package me.somalabs.onepass

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import me.somalabs.onepass.vaultkit.core.CoreLoader
import me.somalabs.onepass.wifi.SuggestionApproval
import me.somalabs.onepass.wifi.SyncReport
import me.somalabs.onepass.wifi.WifiAutomation

/**
 * Loads the Rust core at launch so a broken .so fails here, then shows the
 * settings (the app has no vault screens yet): "Wi-Fi automatique", on by
 * default.
 */
class MainActivity : Activity() {
    private lateinit var wifi: WifiAutomation
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        CoreLoader.ensureLoaded()
        setContentView(R.layout.activity_main)
        wifi = WifiAutomation.get(this)
        status = findViewById(R.id.wifi_auto_status)
        findViewById<Switch>(R.id.wifi_auto).apply {
            isChecked = wifi.enabled
            setOnCheckedChangeListener { _, on -> wifi.enabled = on }
        }
    }

    override fun onResume() {
        super.onResume()
        wifi.onReport = ::render
        render(wifi.lastReport)
        // Picks up an approval given or withdrawn in the system settings.
        wifi.refresh()
    }

    override fun onPause() {
        wifi.onReport = null
        super.onPause()
    }

    private fun render(report: SyncReport?) {
        status.setOnClickListener(null)
        status.text = when {
            report == null -> getString(R.string.wifi_auto_idle)
            !report.enabled -> getString(R.string.wifi_auto_off)
            report.failure != null -> getString(R.string.wifi_auto_failed, report.failure)
            report.installed == 0 -> getString(R.string.wifi_auto_none)
            report.approval == SuggestionApproval.REJECTED -> {
                status.setOnClickListener { openAppSettings() }
                getString(R.string.wifi_auto_rejected)
            }
            report.approval == SuggestionApproval.PENDING ->
                resources.getQuantityString(R.plurals.wifi_auto_installed, report.installed, report.installed) +
                    "\n" + getString(R.string.wifi_auto_pending)
            else -> resources.getQuantityString(R.plurals.wifi_auto_installed, report.installed, report.installed)
        }
        if (report?.showApprovalNotice == true) {
            Toast.makeText(this, R.string.wifi_auto_pending, Toast.LENGTH_LONG).show()
        }
    }

    private fun openAppSettings() {
        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null)))
    }
}
