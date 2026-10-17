package dev.adfection.scanner.vpn

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import dev.adfection.scanner.R
import dev.adfection.scanner.databinding.ActivityProvidersBinding
import java.io.File
import java.io.FileOutputStream

/**
 * "I have no VPN — what can I use?"
 *
 * Reached from the VPN screen. Presents only services that publish importable WireGuard
 * configurations, plus the evidence-backed warning about app-store free VPNs.
 */
class ProvidersActivity : AppCompatActivity() {

    private lateinit var binding: ActivityProvidersBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityProvidersBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val adapter = ProviderAdapter(
            onOpen = { provider -> openUrl(provider.url) },
            onCopyConfig = { provider -> saveGuide(provider) },
        )
        binding.providerList.apply {
            layoutManager = LinearLayoutManager(this@ProvidersActivity)
            this.adapter = adapter
            isNestedScrollingEnabled = false
        }
        adapter.submit(Provider.all(), Provider.freeVpnAppWarning())

        binding.buttonBack.setOnClickListener { finish() }
    }

    private fun openUrl(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, url, Toast.LENGTH_LONG).show()
        }
    }

    /**
     * Write the provider's instructions and link to a text file the user can keep.
     *
     * Written to the app's own external files directory rather than a shared path: this app runs
     * with no storage permission by design and should not request one just to save notes.
     */
    private fun saveGuide(provider: Provider) {
        val text = buildString {
            append(provider.name).append('\n')
            append("=".repeat(provider.name.length)).append("\n\n")
            append("Cost: ").append(provider.cost).append("\n\n")
            append("How to get a config:\n").append(provider.howToGetConfig).append("\n\n")
            append("What the operator sees:\n").append(provider.operatorSees).append("\n\n")
            append("Verdict: ").append(provider.verdict).append("\n\n")
            append("Link: ").append(provider.url).append('\n')
        }

        val dir = File(getExternalFilesDir(null), "providers").apply { mkdirs() }
        val file = File(dir, "${provider.name.replace(Regex("[^A-Za-z0-9]"), "_")}.txt")
        val ok = runCatching {
            FileOutputStream(file).use { it.write(text.toByteArray()) }
        }.isSuccess

        Toast.makeText(
            this,
            if (ok) getString(R.string.provider_saved, file.absolutePath) else getString(R.string.provider_save_failed),
            Toast.LENGTH_LONG,
        ).show()
    }
}
