package dev.adfection.scanner.net

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import dev.adfection.scanner.R
import dev.adfection.scanner.data.Severity
import dev.adfection.scanner.ui.MainActivity

/**
 * Surfaces a detection while the user is not looking at the app.
 *
 * ## Why this is not the same as the foreground notification
 * The foreground notification proves the scanner is running — it is a status light, and it says
 * nothing about what was found. The whole point of a background monitor is to catch the moment a
 * device contacts Candiru infrastructure; if that moment only produces a row in a log the user has to
 * remember to open, the app is a forensic tool and not a detector.
 *
 * ## What is deliberately not notified
 * Only findings at [Severity.HIGH] or above raise an alert. Ad-delivery and tracking domains are
 * *expected* traffic — a browser touches them constantly — so notifying on them would train the user
 * to dismiss notifications, which is worse than staying silent. Blocking still happens and is still
 * logged.
 *
 * Alerts are rate-limited per subject so a retrying client cannot produce a burst.
 */
class AlertNotifier(private val context: Context) {

    private val lastAlerted = java.util.concurrent.ConcurrentHashMap<String, Long>()

    /**
     * Post an alert for a finding, if it clears the severity threshold and the rate limit.
     *

     * @return true when a notification was posted.
     */
    fun alert(subject: String, detail: String, severity: Severity): Boolean {
        if (severity < Severity.HIGH) return false

        val now = System.currentTimeMillis()
        val previous = lastAlerted[subject]
        if (previous != null && now - previous < REPEAT_INTERVAL_MS) return false
        lastAlerted[subject] = now

        return try {
            ensureChannel()
            val open = PendingIntent.getActivity(
                context,
                0,
                Intent(context, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )

            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(
                    context.getString(
                        if (severity == Severity.CRITICAL) R.string.alert_title_critical else R.string.alert_title_high,
                    ),
                )
                .setContentText(subject)
                .setStyle(NotificationCompat.BigTextStyle().bigText("$subject\n\n$detail"))
                .setSmallIcon(R.drawable.ic_shield)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(open)
                .build()

            // Notifications can be disabled by the user or denied at runtime; a detector that throws
            // here would lose the event it was trying to report.
            if (NotificationManagerCompat.from(context).areNotificationsEnabled()) {
                NotificationManagerCompat.from(context).notify(nextId(), notification)
                true
            } else {
                false
            }
        } catch (t: Throwable) {
            android.util.Log.w(TAG, "could not post alert", t)
            false
        }
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.channel_alerts_name),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = context.getString(R.string.channel_alerts_description)
            enableVibration(true)
        }
        manager.createNotificationChannel(channel)
    }

    /** Distinct ids so several alerts do not overwrite each other in the shade. */
    private fun nextId(): Int = (counter.getAndIncrement() % 1000) + ALERT_ID_BASE

    private companion object {
        const val TAG = "AdfectionAlerts"
        const val CHANNEL_ID = "adfection_alerts"
        const val ALERT_ID_BASE = 8800

        /** Per-subject cooldown. Long enough to stop a retry storm, short enough to stay useful. */
        const val REPEAT_INTERVAL_MS = 10 * 60 * 1000L

        val counter = java.util.concurrent.atomic.AtomicInteger(0)
    }
}
