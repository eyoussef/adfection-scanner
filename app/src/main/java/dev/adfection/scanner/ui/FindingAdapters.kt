package dev.adfection.scanner.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import dev.adfection.scanner.R
import dev.adfection.scanner.data.AppFinding
import dev.adfection.scanner.data.PostureFinding
import dev.adfection.scanner.data.Severity
import dev.adfection.scanner.databinding.RowFindingBinding

/** Renders device-posture findings. */
class FindingAdapter : RecyclerView.Adapter<FindingAdapter.Holder>() {

    private val items = ArrayList<PostureFinding>()

    fun submit(findings: List<PostureFinding>) {
        items.clear()
        items.addAll(findings)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(RowFindingBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) = holder.bind(items[position])

    class Holder(private val binding: RowFindingBinding) : RecyclerView.ViewHolder(binding.root) {
        fun bind(finding: PostureFinding) {
            val context = binding.root.context
            binding.textTitle.text = finding.title
            binding.textDetail.text = finding.detail
            binding.textRemediation.text = finding.remediation
            binding.textRemediation.visibility = View.VISIBLE

            val color = severityColor(context, finding.severity)
            binding.textTitle.setTextColor(ContextCompat.getColor(context, color))
            binding.stripe.backgroundTintList = android.content.res.ColorStateList.valueOf(
                ContextCompat.getColor(context, color),
            )
            // Colour is reinforced with the word, so severity survives a colour-vision deficiency.
            binding.textSeverity.text = finding.severity.name
            binding.textSeverity.setTextColor(ContextCompat.getColor(context, color))
        }
    }

    companion object {
        fun severityColor(context: android.content.Context, severity: Severity): Int = when (severity) {
            Severity.CRITICAL -> R.color.severity_critical
            Severity.HIGH -> R.color.severity_high
            Severity.MEDIUM -> R.color.severity_medium
            Severity.LOW -> R.color.severity_low
            Severity.INFO -> R.color.on_surface_muted
        }
    }
}

/** Renders the installed-application risk ranking. */
class AppFindingAdapter : RecyclerView.Adapter<AppFindingAdapter.Holder>() {

    private val items = ArrayList<AppFinding>()

    fun submit(findings: List<AppFinding>) {
        items.clear()
        items.addAll(findings)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(RowFindingBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) = holder.bind(items[position])

    class Holder(private val binding: RowFindingBinding) : RecyclerView.ViewHolder(binding.root) {
        fun bind(finding: AppFinding) {
            val context = binding.root.context
            binding.textTitle.text = context.getString(
                R.string.app_finding_title,
                finding.label,
                finding.riskPoints,
            )
            binding.textDetail.text = buildString {
                append(finding.packageName)
                finding.versionName?.let { append(" v").append(it) }
                finding.installer?.let { append("\nsource: ").append(it) } ?: append("\nsource: sideloaded")
                append("\n")
                append(finding.reasons.joinToString("\n\u2022 ", prefix = "\u2022 "))
            }
            binding.textRemediation.visibility = View.GONE

            val color = FindingAdapter.severityColor(context, finding.severity)
            binding.textTitle.setTextColor(ContextCompat.getColor(context, color))
            binding.stripe.backgroundTintList = android.content.res.ColorStateList.valueOf(
                ContextCompat.getColor(context, color),
            )
            binding.textSeverity.text = finding.severity.name
            binding.textSeverity.setTextColor(ContextCompat.getColor(context, color))
        }
    }
}
