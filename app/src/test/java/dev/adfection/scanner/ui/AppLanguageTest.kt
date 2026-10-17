package dev.adfection.scanner.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Guards the in-app language picker.
 *
 * ## What could go wrong here, and why it is tested
 * The picker itself is trivial; the failure modes are not:
 *
 * 1. **A shipped language missing from the picker.** The app carries six translations, but if an
 *    option is absent from [AppLanguage.options] the translation is unreachable from the UI — the
 *    user would have to change their whole phone's language to see it.
 * 2. **A picker option with no translation behind it.** The reverse: offering "Nederlands" and then
 *    showing English.
 * 3. **The language screen itself not translated.** Changing the language would leave the picker in
 *    English, which is the exact moment a user needs it to be readable.
 *
 * These tests read the resource files directly (no `Context`), which also lets them check all six
 * locales in one run.
 */
class AppLanguageTest {

    private companion object {
        val resDir: File by lazy {
            val candidates = sequence {
                yield(File("src/main/res"))
                yield(File("app/src/main/res"))
                var dir: File? = File("").absoluteFile
                while (dir != null) {
                    yield(File(dir, "src/main/res"))
                    yield(File(dir, "app/src/main/res"))
                    dir = dir.parentFile
                }
            }
            candidates.firstOrNull { File(it, "values/strings.xml").exists() }
                ?: error("could not locate res/values/strings.xml from ${File("").absolutePath}")
        }

        fun parse(dir: File): Map<String, String> {
            val file = File(dir, "strings.xml")
            require(file.exists()) { "missing ${file.path}" }
            val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
            val nodes = doc.getElementsByTagName("string")
            val out = LinkedHashMap<String, String>()
            for (i in 0 until nodes.length) {
                val el = nodes.item(i) as Element
                out[el.getAttribute("name")] = el.textContent
            }
            return out
        }
    }

    private val english by lazy { parse(File(resDir, "values")) }

    @Test
    fun `every shipped locale is offered in the picker`() {
        val shipped = listOf("fr", "it", "de", "es", "pt", "ar")
        val offered = AppLanguage.options.map { it.tag }.toSet()

        for (locale in shipped) {
            assertTrue(
                "locale '$locale' has translations but no picker entry, so it is unreachable",
                offered.contains(locale),
            )
        }
    }

    @Test
    fun `the picker offers no language the app cannot display`() {
        val shipped = listOf("fr", "it", "de", "es", "pt", "ar") + "en"

        for (option in AppLanguage.options) {
            if (option.tag.isEmpty()) continue
            assertTrue(
                "picker offers '${option.tag}' (${option.label}) but no values-${option.tag} exists",
                shipped.contains(option.tag),
            )
        }
    }

    @Test
    fun `system default is the first option`() {
        // It must be reachable without scrolling and be the obvious default, because "follow my
        // phone" is what most users want and is the pre-existing behaviour.
        assertEquals("", AppLanguage.options.first().tag)
    }

    @Test
    fun `language labels are written in their own language`() {
        // A picker is scanned by someone looking for their own word.
        val labels = AppLanguage.options.associate { it.tag to it.label }
        assertEquals("Français", labels["fr"])
        assertEquals("Español", labels["es"])
        assertEquals("Deutsch", labels["de"])
        assertEquals("Italiano", labels["it"])
        assertEquals("Português", labels["pt"])
        assertEquals("العربية", labels["ar"])
        assertEquals("English", labels["en"])
    }

    @Test
    fun `the language screen is itself translated in every locale`() {
        val keys = listOf(
            "section_language",
            "language_title",
            "language_change",
            "language_picker_title",
            "language_following_system",
            "language_following_system_named",
            "language_note",
            "language_system_default",
        )

        for (locale in listOf("fr", "it", "de", "es", "pt", "ar")) {
            val table = parse(File(resDir, "values-$locale"))
            for (key in keys) {
                val value = table[key]
                assertTrue("$locale is missing '$key'", value != null)
                assertFalse(
                    "$locale/$key is still English — the picker would not be readable after switching",
                    value == english[key],
                )
            }
        }
    }

    /**
     * The reassurance that only this app changes is the single most important sentence on the
     * dialog: without it a user may reasonably fear the picker changes their whole phone.
     */
    @Test
    fun `the note explaining the scope is translated everywhere`() {
        for (locale in listOf("fr", "it", "de", "es", "pt", "ar")) {
            val table = parse(File(resDir, "values-$locale"))
            val note = table["language_note"]
            assertTrue("$locale has no language_note", note != null)
            assertTrue("$locale note is too short to explain the scope", (note ?: "").length > 30)
            assertFalse("$locale note is still English", note == english["language_note"])
        }
    }

    @Test
    fun `language_system_default is a distinct label per locale`() {
        val seen = mutableMapOf<String, String>()
        seen["en"] = english["language_system_default"]!!
        for (locale in listOf("fr", "it", "de", "es", "pt", "ar")) {
            seen[locale] = parse(File(resDir, "values-$locale"))["language_system_default"]!!
        }
        // Latin-script locales should differ from English; Arabic and English obviously differ.
        assertEquals("System default", seen["en"])
        assertFalse(seen["fr"] == seen["en"])
        assertFalse(seen["de"] == seen["en"])
        assertFalse(seen["ar"] == seen["en"])
    }
}
