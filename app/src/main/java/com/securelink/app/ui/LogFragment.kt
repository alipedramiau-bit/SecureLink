package com.securelink.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.securelink.app.R
import com.securelink.app.databinding.FragmentLogBinding
import com.securelink.app.vpn.VpnLog

/**
 * صفحه گزارش عیب‌یابی (Diagnostics):
 * رویدادهای اتصال/قطع VPN را روی خود گوشی نشان می‌دهد تا کاربر بدون adb بتواند
 * علت قطع‌شدن را ببیند و برای عیب‌یابی کپی/اشتراک‌گذاری کند.
 *
 * بروزرسانی خودکار: هر ثانیه یک‌بار فقط اگر version گزارش تغییر کرده باشد.
 */
class LogFragment : Fragment() {

    private var _binding: FragmentLogBinding? = null
    private val binding get() = _binding!!

    private val handler = Handler(Looper.getMainLooper())
    private var lastVersionSeen = -1L

    private val refreshTick = object : Runnable {
        override fun run() {
            if (_binding == null) return
            if (VpnLog.version != lastVersionSeen) render()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentLogBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        (requireActivity() as? androidx.appcompat.app.AppCompatActivity)
            ?.supportActionBar?.title = getString(R.string.log_title)

        binding.btnCopy.setOnClickListener { copyLog() }
        binding.btnShare.setOnClickListener { shareLog() }
        binding.btnClear.setOnClickListener {
            VpnLog.clear()
            render()
            Toast.makeText(requireContext(), R.string.log_cleared, Toast.LENGTH_SHORT).show()
        }

        render()
    }

    override fun onResume() {
        super.onResume()
        handler.post(refreshTick)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(refreshTick)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        handler.removeCallbacks(refreshTick)
        _binding = null
    }

    // ------------------------------------------------------------------

    private fun render() {
        lastVersionSeen = VpnLog.version

        // کارت آخرین علت قطع‌شدن
        val err = VpnLog.lastL2tpError
        if (err != null) {
            binding.cardLastError.visibility = View.VISIBLE
            binding.tvLastError.text = err
        } else {
            binding.cardLastError.visibility = View.GONE
        }

        // متن گزارش
        val text = if (VpnLog.lineCount() == 0) {
            getString(R.string.log_empty)
        } else {
            VpnLog.snapshot()
        }
        binding.tvLog.text = text
    }

    private fun copyLog() {
        val text = VpnLog.snapshot()
        if (text.isBlank()) {
            Toast.makeText(requireContext(), R.string.log_empty, Toast.LENGTH_SHORT).show()
            return
        }
        val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(getString(R.string.log_title), text))
        Toast.makeText(requireContext(), R.string.log_copied, Toast.LENGTH_SHORT).show()
    }

    private fun shareLog() {
        val text = VpnLog.snapshot()
        if (text.isBlank()) {
            Toast.makeText(requireContext(), R.string.log_empty, Toast.LENGTH_SHORT).show()
            return
        }
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, getString(R.string.log_share_subject))
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(intent, getString(R.string.log_share)))
    }
}
