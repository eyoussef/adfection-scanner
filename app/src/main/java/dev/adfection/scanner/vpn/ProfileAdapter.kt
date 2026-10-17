package dev.adfection.scanner.vpn

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import dev.adfection.scanner.R
import dev.adfection.scanner.databinding.RowProfileBinding

/** Lists stored WireGuard profiles with connect / inspect / delete actions. */
class ProfileAdapter(
    private val onConnect: (WireGuardProfiles.Entry) -> Unit,
    private val onDelete: (WireGuardProfiles.Entry) -> Unit,
    private val onShow: (WireGuardProfiles.Entry) -> Unit,
) : RecyclerView.Adapter<ProfileAdapter.Holder>() {

    private val items = ArrayList<WireGuardProfiles.Entry>()

    fun submit(entries: List<WireGuardProfiles.Entry>) {
        items.clear()
        items.addAll(entries)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(RowProfileBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) = holder.bind(items[position])

    inner class Holder(private val binding: RowProfileBinding) : RecyclerView.ViewHolder(binding.root) {

        fun bind(entry: WireGuardProfiles.Entry) {
            val context = binding.root.context
            binding.textProfileName.text = entry.name

            binding.textProfileMeta.text = if (entry.isValid) {
                val config = entry.config!!
                val endpoint = config.peers.firstOrNull()?.endpoint?.orElse(null)?.toString() ?: "no endpoint"
                val dns = config.`interface`.dnsServers.joinToString(", ").ifEmpty { "system DNS" }
                context.getString(R.string.vpn_profile_meta, endpoint, dns)
            } else {
                context.getString(R.string.vpn_profile_invalid, entry.error ?: "unknown error")
            }

            // A profile that failed to parse cannot be connected to; say so instead of failing later.
            binding.buttonProfileConnect.isEnabled = entry.isValid
            binding.buttonProfileConnect.alpha = if (entry.isValid) 1f else 0.4f

            binding.buttonProfileConnect.setOnClickListener { onConnect(entry) }
            binding.textProfileName.setOnClickListener { onShow(entry) }
            binding.buttonProfileDelete.setOnClickListener { onDelete(entry) }
        }
    }
}
