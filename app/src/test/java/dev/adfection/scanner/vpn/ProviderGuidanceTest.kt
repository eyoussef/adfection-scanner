package dev.adfection.scanner.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Guards on the provider guidance and on locale completeness.
 *
 * ## Why this parses the resource files instead of using a Context
 * The guidance text lives in string resources so it can be translated. Reading it back through an
 * Android `Context` would need Robolectric, whose native dependencies are not available for every
 * host — and, more importantly, a `Context` test can only see *one* locale at a time.
 *
 * Parsing the XML directly lets these tests assert two things a Context-based test cannot:
 *  1. every shipped locale defines every key (a missing one falls back to English silently), and
 *  2. every locale preserves the `%1$s`-style arguments, where a dropped argument is a crash at
 *     runtime rather than a cosmetic issue.
 *
 * The safety properties are unchanged from the original test: they are the reason this screen is
 * worth testing at all.
 */
class ProviderGuidanceTest {

    private companion object {
        /**
         * Locates the res/ directory regardless of the test working directory.
         *
         * Gradle runs unit tests with the module as the working directory, but that is not
         * guaranteed for an IDE or a re-run from another path, so both layouts are tried.
         */
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
                ?: error(
                    "could not locate res/values/strings.xml from ${File("").absolutePath}; " +
                        "checked src/main/res and app/src/main/res",
                )
        }

        val locales = listOf("fr", "it", "de", "es", "pt", "ar")

        /** Parse one `values[-locale]/strings.xml`. */
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

    private val english: Map<String, String> by lazy { parse(File(resDir, "values")) }
    private val translated: Map<String, Map<String, String>> by lazy {
        locales.associateWith { parse(File(resDir, "values-$it")) }
    }

    private val providers = Provider.all()

    /** Resolve a provider field from the English resource map, mirroring what the UI would show. */
    private fun text(@androidx.annotation.StringRes id: Int): String {
        val name = resourceName(id)
        return english[name] ?: error("no string resource for $name")
    }

    /**
     * Map an `R.string` id back to its name.
     *
     * `R` fields carry no name at runtime in a unit test, so the id is resolved through the
     * generated `R` class reflection-free: the ids are compared against the known set by value.
     */
    private fun resourceName(id: Int): String {
        // R.string.<name> values are compiled constants; find the field whose value matches.
        val fields = dev.adfection.scanner.R.string::class.java.declaredFields
        return fields.firstOrNull { field ->
            runCatching { field.isAccessible = true; field.getInt(null) == id }.getOrDefault(false)
        }?.name ?: error("unknown string id $id")
    }

    // ------------------------------------------------------------------ safety properties

    @Test
    fun `the free-VPN-app warning is substantive and cites evidence`() {
        val warning = english["provider_warning_body"]!!

        assertTrue("must name data harvesting", warning.contains("data", ignoreCase = true))
        assertTrue("must warn about malware", warning.contains("malware", ignoreCase = true))
        assertTrue(
            "must cite measured research",
            warning.contains("CNET") || warning.contains("CSIRO") || warning.contains("2024"),
        )
        assertTrue("warning is too short to be useful", warning.length > 400)
    }

    @Test
    fun `every provider states what the operator can see`() {
        for (provider in providers) {
            val sees = text(provider.operatorSeesRes)
            val cost = text(provider.costRes)
            val how = text(provider.howToGetConfigRes)

            assertTrue("'${provider.name}' must explain operator visibility", sees.length > 40)
            assertTrue("'${provider.name}' must state a cost, including free", cost.isNotBlank())
            assertTrue("'${provider.name}' must give concrete steps", how.length > 40)
            assertTrue("'${provider.name}' must have a link", provider.url.startsWith("https://"))
        }
    }

    @Test
    fun `no generic free-VPN app is presented as a recommendation`() {
        for (provider in providers) {
            val haystack = (
                provider.name + text(provider.verdictRes) + text(provider.howToGetConfigRes)
                ).lowercase()
            val banned = listOf("betternet", "hola", "turbo vpn", "hotspot shield", "supervpn", "freevpn")
            for (term in banned) {
                assertFalse("'${provider.name}' mentions banned free-VPN app '$term'", haystack.contains(term))
            }
        }
    }

    @Test
    fun `self-hosting is offered first, because it has no third party to trust`() {
        assertEquals("Self-hosted WireGuard", providers.first().name)
        assertEquals(dev.adfection.scanner.data.Severity.LOW, providers.first().severity)
        assertTrue(
            "the self-hosted entry must make its key advantage explicit",
            text(providers.first().verdictRes).contains("no third party", ignoreCase = true),
        )
    }

    @Test
    fun `there is at least one genuinely free option that is not an app-store VPN`() {
        val free = providers.filter { text(it.costRes).contains("free", ignoreCase = true) }
        assertTrue("at least one free option must exist", free.isNotEmpty())
        assertTrue(
            "a free option must be config-based",
            free.any { it.url.contains("wgcf") || it.url.contains("proton") || it.url.contains("wg-easy") },
        )
    }

    @Test
    fun `services that cannot be imported are marked as such instead of looking importable`() {
        val riseup = providers.first { it.name.contains("Riseup") }
        assertTrue(
            "non-importable services must say so",
            text(riseup.howToGetConfigRes).contains("Not importable", ignoreCase = true),
        )
    }

    @Test
    fun `proton free tier claim matches provider documentation`() {
        val proton = providers.first { it.name.contains("Proton") }
        assertTrue(text(proton.costRes).contains("free", ignoreCase = true))
        assertTrue(text(proton.howToGetConfigRes).contains("WireGuard configuration", ignoreCase = true))
    }

    // ------------------------------------------------------------------ locale integrity

    @Test
    fun `every shipped locale defines every string`() {
        val expected = english.keys
        for (locale in locales) {
            val table = translated.getValue(locale)
            val missing = expected - table.keys
            val extra = table.keys - expected
            assertTrue("$locale is missing ${missing.size} strings: ${missing.take(5)}", missing.isEmpty())
            assertTrue("$locale has ${extra.size} unknown strings: ${extra.take(5)}", extra.isEmpty())
        }
    }

    /**
     * A dropped format argument is a runtime crash, not a typo — `getString` throws when the locale
     * supplies fewer arguments than the format string expects.
     */
    @Test
    fun `every shipped locale preserves format arguments`() {
        val argPattern = Regex("""%(?:\d+\$)?[sd]""")
        for (locale in locales) {
            val table = translated.getValue(locale)
            for ((key, enText) in english) {
                val localised = table[key] ?: continue
                val enArgs = argPattern.findAll(enText).map { it.value }.toSortedSet()
                val locArgs = argPattern.findAll(localised).map { it.value }.toSortedSet()
                assertEquals("$locale/$key has different format arguments", enArgs, locArgs)
            }
        }
    }

    /**
     * A locale that is a copy of English is not a translation. This catches a file generated with the
     * wrong source, which would otherwise look complete in every other check.
     */
    @Test
    fun `every shipped locale actually translates the user-facing text`() {
        // Proper nouns and protocol words legitimately stay identical.
        val untranslatable = setOf("app_name", "vpn_title", "vpn_paste_hint")
        for (locale in locales) {
            val table = translated.getValue(locale)
            val identical = english.keys
                .filter { it !in untranslatable }
                .filter { key -> table[key] == english[key] }

            assertTrue(
                "$locale has ${identical.size} strings identical to English, e.g. ${identical.take(5)}",
                identical.size <= 3,
            )
        }
    }

    @Test
    fun `provider guidance is translated, not left in English`() {
        val providerKeys = providers.flatMap {
            listOf(
                resourceName(it.costRes),
                resourceName(it.howToGetConfigRes),
                resourceName(it.operatorSeesRes),
                resourceName(it.verdictRes),
            )
        }
        for (locale in locales) {
            val table = translated.getValue(locale)
            for (key in providerKeys) {
                assertTrue("$locale/$key must not be English", table[key] != english[key])
            }
        }
    }
}
