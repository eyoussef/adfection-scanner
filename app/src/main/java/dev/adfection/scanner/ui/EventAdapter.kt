package dev.adfection.scanner.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import dev.adfection.scanner.R
import dev.adfection.scanner.data.Action
import dev.adfection.scanner.data.ScanEvent
import dev.adfection.scanner.data.Severity
import dev.adfection.scanner.databinding.RowEventBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Renders the evidence log. */
class EventAdapter : RecyclerView.Adapter<EventAdapter.Holder>() {

    private val events = ArrayList<ScanEvent>()
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun submit(items: List<ScanEvent>) {
        events.clear()
        events.addAll(items)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val binding = RowEventBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return Holder(binding)
    }

    override fun getItemCount(): Int = events.size

    override fun onBindViewHolder(holder: Holder, position: Int) = holder.bind(events[position])

    inner class Holder(private val binding: RowEventBinding) : RecyclerView.ViewHolder(binding.root) {

        fun bind(event: ScanEvent) {
            val context = binding.root.context

            binding.textTime.text = timeFormat.format(Date(event.timestamp))
            binding.textSubject.text = event.subject
            binding.textDetail.text = event.detail
            binding.textKind.text = buildString {
                append(event.kind.name.replace('_', ' '))
                event.category?.let { append(" \u00b7 ").append(it.name.replace('_', ' ')) }
                append(" \u00b7 ").append(event.action.name)
            }

            val colorRes = when {
                event.action == Action.BLOCKED -> R.color.severity_critical
                event.severity == Severity.HIGH -> R.color.severity_high
                event.severity == Severity.MEDIUM -> R.color.severity_medium
                else -> R.color.on_surface_muted
            }
            // Tint rather than set the background colour: the stripe is a rounded drawable, and replacing
            // its background would square off the card's corner.
            binding.stripe.backgroundTintList = android.content.res.ColorStateList.valueOf(
                ContextCompat.getColor(context, colorRes),
            )
            binding.textSubject.setTextColor(ContextCompat.getColor(context, colorRes))
        }
    }
}
