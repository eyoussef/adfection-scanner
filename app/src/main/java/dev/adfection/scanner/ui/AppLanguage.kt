package dev.adfection.scanner.ui

import android.content.Context
import android.os.Build
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import dev.adfection.scanner.R

/**
 * Per-app language selection.
 *
 * ## Why the app needs its own picker
 * Android normally applies the *system* language to all apps. That means a reader who wants this
 * app in Arabic — because they are being targeted and want to understand the findings in their own
 * language — would otherwise have to change their entire phone's language. That is a bad trade for
 * a security tool: it changes the whole device to fix one app.
 *
 * ## How it is implemented
 * [AppCompatDelegate.setApplicationLocales] stores a per-app locale that Android applies to this
 * app only. On API 33+ AppCompat hands the preference to the platform, so the system's own
 * "App languages" screen agrees with the in-app choice; below that AppCompat persists and applies it
 * itself. Either way the change takes effect immediately, without restarting the process.
 *
 * ## What "follow system" means
 * An empty [LocaleListCompat] means "no override": the app uses whatever the device is set to. That
 * is the default, and it is the right default — a device already in French should show French
 * without the user doing anything.
 */
object AppLanguage {

    /** A language the app ships, with the endonym so each is readable to its own speakers. */
    data class Option(val tag: String, val label: String)

    /**
     * The shipped languages.
     *
     * Labels are endonyms (Français, not French) because a picker is read by someone who speaks the
     * language they are looking for, and they will scan for their own word first.
     */
    val options: List<Option> = listOf(
        // Label resolved at display time so "System default" is translated too.
        Option("", ""),
        Option("en", "English"),
        Option("fr", "Français"),
        Option("es", "Español"),
        Option("de", "Deutsch"),
        Option("it", "Italiano"),
        Option("pt", "Português"),
        Option("ar", "العربية"),
    )

    /** Display label for [option], translating the "system default" entry. */
    fun displayLabel(context: Context, option: Option): String =
        if (option.tag.isEmpty()) context.getString(R.string.language_system_default) else option.label

    /** The language tag currently applied to this app, or "" when following the system. */
    fun currentTag(): String = AppCompatDelegate.getApplicationLocales().toLanguageTags()

    /**
     * The label for the active choice, for display next to the picker.
     *
     * Falls back to the tag itself when a locale is active that is not in [options] — which happens
     * when the device is set to a language this app does not ship, and is more honest than claiming
     * "English".
     */
    fun currentLabel(context: Context): String {
        val tag = currentTag()
        if (tag.isBlank()) {
            val system = systemLanguageTag()
            val shipped = options.firstOrNull { it.tag.isNotEmpty() && tagMatches(system, it.tag) }
            return if (shipped != null) {
                context.getString(R.string.language_following_system_named, shipped.label)
            } else {
                context.getString(R.string.language_following_system)
            }
        }
        // A tag may carry a region ("pt-BR"); match on the language subtag.
        return options.firstOrNull { it.tag.isNotEmpty() && tagMatches(tag, it.tag) }?.label ?: tag
    }

    /** Apply [tag]. An empty tag clears the override and returns to the system language. */
    fun apply(tag: String) {
        val locales = if (tag.isBlank()) {
            LocaleListCompat.getEmptyLocaleList()
        } else {
            LocaleListCompat.forLanguageTags(tag)
        }
        AppCompatDelegate.setApplicationLocales(locales)
    }

    /** Two-letter code to show in the title chip. */
    fun currentChipLabel(): String {
        val tag = currentTag().ifBlank { systemLanguageTag() }
        val language = tag.substringBefore('-').substringBefore('_')
        return if (language.isBlank()) "AUTO" else language.uppercase()
    }

    private fun systemLanguageTag(): String {
        val locales = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val configuration = android.content.res.Resources.getSystem().configuration
            configuration.locales
        } else {
            null
        }
        return if (locales != null && !locales.isEmpty) {
            locales.get(0)?.toLanguageTag().orEmpty()
        } else {
            java.util.Locale.getDefault().toLanguageTag()
        }
    }

    private fun tagMatches(a: String, b: String): Boolean {
        val la = a.substringBefore('-').substringBefore('_').lowercase()
        val lb = b.substringBefore('-').substringBefore('_').lowercase()
        return la.isNotEmpty() && la == lb
    }
}
