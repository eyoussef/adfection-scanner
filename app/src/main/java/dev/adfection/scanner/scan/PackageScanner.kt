package dev.adfection.scanner.scan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import dev.adfection.scanner.data.AppFinding
import dev.adfection.scanner.data.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * Installed-application audit.
 *
 * This is an *audit*, not a malware verdict engine: it ranks apps by concrete, checkable signals a
 * defender can act on. Every point awarded maps to one entry in [reasons], so a finding can always
 * be explained to the user. No app is described as malicious on the basis of name similarity alone.
 */
class PackageScanner(private val context: Context) {

    private val pm: PackageManager = context.packageManager

    suspend fun scan(): List<AppFinding> = withContext(Dispatchers.IO) {
        val packages: List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        packages.mapNotNull { evaluate(it) }
            .filter { it.riskPoints > 0 }
            .sortedWith(compareByDescending<AppFinding> { it.riskPoints }.thenBy { it.label })
    }

    private fun evaluate(info: PackageInfo): AppFinding? {
        val app = info.applicationInfo ?: return null
        // Only user-facing apps: system apps produce noise and cannot be removed anyway.
        val isSystem = (app.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
        if (isSystem) return null

        val requested = info.requestedPermissions?.toSet() ?: emptySet()
        val reasons = ArrayList<String>(6)
        var points = 0

        fun award(weight: Int, reason: String) {
            points += weight
            reasons.add(reason)
        }

        // A spyware implant on a stock device must obtain a path to intercept content or install
        // code. These permissions are the ones that path requires.
        if (requested.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
            award(20, "Declares an accessibility service")
        }
        if (requested.contains("android.permission.SYSTEM_ALERT_WINDOW")) {
            award(25, "Requests draw-over-other-apps")
        }
        if (requested.contains("android.permission.REQUEST_INSTALL_PACKAGES")) {
            award(20, "Can install other packages")
        }
        if (requested.contains("android.permission.READ_SMS") || requested.contains("android.permission.RECEIVE_SMS")) {
            award(25, "Reads or receives SMS (2FA interception)")
        }
        if (requested.contains("android.permission.RECORD_AUDIO") &&
            requested.contains("android.permission.ACCESS_FINE_LOCATION")
        ) {
            award(15, "Microphone + precise location together")
        }
        if (requested.contains("android.permission.CALL_PHONE") && requested.contains("android.permission.READ_CONTACTS")) {
            award(10, "Place calls and read contacts")
        }
        if (requested.contains("android.permission.QUERY_ALL_PACKAGES")) {
            award(5, "Enumerates all installed packages")
        }

        val installer = installerOf(info)
        if (installer == null && !isSystem) {
            award(20, "Sideloaded (no installer of record)")
        } else if (installer != null && installer !in KNOWN_STORES) {
            award(10, "Installed from an unrecognised source: $installer")
        }

        // An app that hides itself from the launcher but does work in the background is a
        // legitimate pattern for a few apps and a common one for implants.
        val launcherIntent = pm.getLaunchIntentForPackage(info.packageName)
        val hasServices = (info.services?.isNotEmpty() == true)
        if (launcherIntent == null && hasServices) {
            award(15, "No launcher icon but declares services (background-only)")
        }

        // Debuggable user apps allow a host to attach and read memory/state.
        if ((app.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            award(15, "Debuggable build")
        }

        // A very small payload that ships many of the risky permissions above is characteristic of
        // a dropper; this is a weak signal on its own and weighted accordingly.
        val sizeBytes = runCatching { java.io.File(app.sourceDir).length() }.getOrDefault(0L)
        if (sizeBytes in 1..(200 * 1024) && points >= 40) {
            award(10, "Small payload (${sizeBytes / 1024} KiB) with high-impact permission set")
        }

        if (points == 0) return null

        val label = runCatching { pm.getApplicationLabel(app).toString() }.getOrDefault(info.packageName)
        val versionName = runCatching { info.versionName }.getOrNull()

        return AppFinding(
            packageName = info.packageName,
            label = label,
            riskPoints = points,
            reasons = reasons,
            severity = when {
                points >= 70 -> Severity.CRITICAL
                points >= 45 -> Severity.HIGH
                points >= 25 -> Severity.MEDIUM
                else -> Severity.LOW
            },
            installer = installer,
            versionName = versionName,
        )
    }

    private fun installerOf(info: PackageInfo): String? =
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val source = pm.getInstallSourceInfo(info.packageName)
                source.installingPackageName ?: source.initiatingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(info.packageName)
            }
        }.getOrNull()

    /** SHA-256 of an APK, so a finding can be checked against the published implant hash set. */
    fun apkHash(packageName: String): String? = runCatching {
        val app = pm.getApplicationInfo(packageName, 0)
        val digest = MessageDigest.getInstance("SHA-256")
        java.io.File(app.sourceDir).inputStream().use { stream ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = stream.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()

    private companion object {
        val KNOWN_STORES = setOf(
            "com.android.vending",
            "com.google.android.packageinstaller",
            "com.samsung.android.galaxyapps",
            "com.amazon.venezia",
            "org.fdroid.fdroid",
        )
    }
}
