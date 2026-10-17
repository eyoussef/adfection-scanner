package dev.adfection.scanner.vpn

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import dev.adfection.scanner.R
import dev.adfection.scanner.databinding.RowProviderBinding

/**
 * Renders provider guidance, including the warning about free VPN apps.
 *
 * The warning is a fixed, non-dismissible row rendered by this adapter rather than something a
 * caller can forget to add, because it is the single most consequential piece of text for a user
 * who has no VPN yet.
 */
class ProviderAdapter(
    private val onOpen: (Provider) -> Unit,
    private val onCopyConfig: (Provider) -> Unit,
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    private val items = ArrayList<Item>()

    sealed interface Item {
        data class Warning(val text: String) : Item
        data class Entry(val provider: Provider) : Item
    }

    fun submit(providers: List<Provider>, warning: String) {
        items.clear()
        items.add(Item.Warning(warning))
        providers.forEach { items.add(Item.Entry(it)) }
        notifyDataSetChanged()
    }

    override fun getItemViewType(position: Int): Int = when (items[position]) {
        is Item.Warning -> TYPE_WARNING
        is Item.Entry -> TYPE_PROVIDER
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return when (viewType) {
            TYPE_WARNING -> WarningHolder(
                dev.adfection.scanner.databinding.RowProviderWarningBinding
                    .inflate(inflater, parent, false),
            )

            else -> Holder(
                RowProviderBinding.inflate(inflater, parent, false),
                onOpen,
                onCopyConfig,
            )
        }
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val item = items[position]) {
            is Item.Warning -> (holder as WarningHolder).bind(item.text)
            is Item.Entry -> (holder as Holder).bind(item.provider)
        }
    }

    class WarningHolder(
        private val binding: dev.adfection.scanner.databinding.RowProviderWarningBinding,
    ) : RecyclerView.ViewHolder(binding.root) {
        fun bind(text: String) {
            binding.textWarning.text = text
        }
    }

    class Holder(
        private val binding: RowProviderBinding,
        private val onOpen: (Provider) -> Unit,
        private val onCopyConfig: (Provider) -> Unit,
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(provider: Provider) {
            val context = binding.root.context

            binding.textProviderName.text = provider.name
            binding.textProviderCost.text = provider.cost
            binding.textProviderHow.text = provider.howToGetConfig
            binding.textProviderSees.text = context.getString(R.string.provider_operator_sees, provider.operatorSees)
            binding.textProviderVerdict.text = provider.verdict

            val colourRes = when (provider.severity) {
                dev.adfection.scanner.data.Severity.LOW -> R.color.severity_low
                dev.adfection.scanner.data.Severity.MEDIUM -> R.color.severity_medium
                dev.adfection.scanner.data.Severity.HIGH -> R.color.severity_high
                else -> R.color.severity_critical
            }
            binding.textProviderName.setTextColor(ContextCompat.getColor(context, colourRes))
            binding.stripe.backgroundTintList = android.content.res.ColorStateList.valueOf(
                ContextCompat.getColor(context, colourRes),
            )

            binding.root.setOnClickListener { onOpen(provider) }

            // Only services that publish an importable .conf get the copy affordance.
            val importable = provider.url.contains("wgcf") ||
                provider.url.contains("proton") ||
                provider.url.contains("wg-easy") ||
                provider.url.contains("mullvad") ||
                provider.url.contains("ivpn")
            binding.buttonProviderCopy.visibility = if (importable) View.VISIBLE else View.GONE
            binding.buttonProviderCopy.setOnClickListener { onCopyConfig(provider) }
        }
    }

    private companion object {
        const val TYPE_WARNING = 0
        const val TYPE_PROVIDER = 1
    }
}
