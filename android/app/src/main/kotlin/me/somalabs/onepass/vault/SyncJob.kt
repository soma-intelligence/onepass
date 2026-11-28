package me.somalabs.onepass.vault

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import me.somalabs.onepass.vaultkit.core.CoreLoader

/**
 * The periodic background round (no WorkManager without AndroidX): about
 * every 15 minutes, Android's floor, with a network. A round without an
 * unlocked session still fetches and sends what is pending; held vaults send
 * nothing and nothing is decrypted. An account kept on this device has
 * nothing to do. Not persisted across reboots (no boot permission): the
 * next launch schedules it again.
 */
class SyncJob : JobService() {
    @Volatile private var worker: Thread? = null

    override fun onStartJob(params: JobParameters): Boolean {
        worker = Thread({
            runCatching {
                CoreLoader.ensureLoaded()
                SyncManager.get(applicationContext).roundForJob()
            }
            jobFinished(params, false)
        }, "onepass-sync-job").apply { isDaemon = true; start() }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        worker?.interrupt()
        return true
    }

    companion object {
        private const val JOB_ID = 0x0E9A55

        fun schedule(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            if (scheduler.getPendingJob(JOB_ID) != null) return
            val job = JobInfo.Builder(JOB_ID, ComponentName(context, SyncJob::class.java))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPeriodic(15 * 60 * 1000L)
                .build()
            runCatching { scheduler.schedule(job) }
        }
    }
}
