package com.securelink.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.securelink.app.R
import com.securelink.app.data.ProfileType
import com.securelink.app.data.VpnProfile
import com.securelink.app.databinding.ItemProfileBinding

/**
 * آداپتر لیست پروفایل‌ها.
 *
 * @param isConnected تابع تعیین وضعیت اتصال هر پروفایل ( توسط فرگمنت ارائه می‌شود)
 */
class ProfileAdapter(
    private val isConnected: (VpnProfile) -> Boolean,
    private val onToggle: (VpnProfile) -> Unit,
    private val onEdit: (VpnProfile) -> Unit
) : RecyclerView.Adapter<ProfileAdapter.ViewHolder>() {

    private val items: MutableList<VpnProfile> = mutableListOf()

    fun submit(list: List<VpnProfile>) {
        items.clear()
        items.addAll(list)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemProfileBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(items[position])
    }

    inner class ViewHolder(
        private val binding: ItemProfileBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(profile: VpnProfile) {
            val context = binding.root.context
            val connected = isConnected(profile)

            binding.tvName.text = profile.name
            binding.tvSummary.text = profile.summary()
            binding.tvType.text = when (profile.type) {
                ProfileType.WIREGUARD -> context.getString(R.string.type_wireguard)
                ProfileType.IKEV2 -> context.getString(R.string.type_ikev2)
                ProfileType.L2TP -> context.getString(R.string.type_l2tp)
            }

            binding.tvStatus.text = if (connected) {
                context.getString(R.string.status_connected)
            } else {
                context.getString(R.string.status_disconnected)
            }
            val statusColor = ContextCompat.getColor(
                context, if (connected) R.color.status_connected else R.color.status_disconnected
            )
            binding.statusDot.background?.setTint(statusColor)
            binding.tvStatus.setTextColor(statusColor)

            binding.btnConnect.text = if (connected) {
                context.getString(R.string.disconnect)
            } else {
                context.getString(R.string.connect)
            }
            binding.btnConnect.setOnClickListener { onToggle(profile) }
            binding.root.setOnClickListener { onEdit(profile) }
        }
    }
}
