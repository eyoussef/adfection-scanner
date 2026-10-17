package dev.adfection.scanner.engine

import dev.adfection.scanner.data.Ioc
import dev.adfection.scanner.data.IocType
import dev.adfection.scanner.data.Severity
import dev.adfection.scanner.data.ThreatCategory

/**
 * Parses the bundled, tab-separated indicator file.
 *
 * Format (one indicator per line):
 * ```
 * # comment
 * type<TAB>value<TAB>category<TAB>severity<TAB>source<TAB>note
 * ```
 * Blank lines and `#` comments are ignored. Malformed lines are skipped and reported through
 * [problems] instead of aborting the load, so a bad hand-edit can never brick the scanner.
 */
object TsvIocLoader {

    data class Result(val iocs: List<Ioc>, val problems: List<String>) {
        fun toMatcher(): IocMatcher = IocMatcher(iocs)
    }

    fun parse(text: String): Result {
        val iocs = ArrayList<Ioc>()
        val problems = ArrayList<String>()

        text.lineSequence().forEachIndexed { index, rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEachIndexed

            val cols = line.split('\t').map { it.trim() }
            if (cols.size < 5) {
                problems.add("line ${index + 1}: expected >=5 columns, found ${cols.size}")
                return@forEachIndexed
            }

            val type = enumOrNull<IocType>(cols[0])
            if (type == null) {
                problems.add("line ${index + 1}: unknown indicator type '${cols[0]}'")
                return@forEachIndexed
            }
            val category = enumOrNull<ThreatCategory>(cols[2])
            if (category == null) {
                problems.add("line ${index + 1}: unknown category '${cols[2]}'")
                return@forEachIndexed
            }
            val value = cols[1]
            if (value.isEmpty()) {
                problems.add("line ${index + 1}: empty value")
                return@forEachIndexed
            }
            if (type == IocType.SHA256 && value.length != 64) {
                problems.add("line ${index + 1}: sha256 value has length ${value.length}, expected 64")
                return@forEachIndexed
            }
            if (type == IocType.IP && Ipv4Cidr.toLong(value) == null && !value.contains(':')) {
                problems.add("line ${index + 1}: '$value' is not a valid IPv4/IPv6 literal")
                return@forEachIndexed
            }
            if (type == IocType.CIDR && Ipv4Cidr.parse(value) == null) {
                problems.add("line ${index + 1}: '$value' is not a supported IPv4 CIDR range")
                return@forEachIndexed
            }

            iocs.add(
                Ioc(
                    type = type,
                    value = value,
                    category = category,
                    severity = Severity.parse(cols[3]),
                    source = cols[4],
                    note = cols.getOrElse(5) { "" },
                )
            )
        }

        return Result(iocs, problems)
    }

    private inline fun <reified T : Enum<T>> enumOrNull(raw: String): T? =
        enumValues<T>().firstOrNull { it.name.equals(raw.trim(), ignoreCase = true) }
}
