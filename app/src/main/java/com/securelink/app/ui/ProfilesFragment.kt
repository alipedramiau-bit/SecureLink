package com.securelink.app.ui

import android.app.Activity
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import com.securelink.app.R
import com.securelink.app.data.ProfileStore
import com.securelink.app.data.ProfileType
import com.securelink.app.data.VpnProfile
import com.securelink.app.databinding.FragmentProfilesBinding
import com.securelink.app.vpn.L2tpVpnService
import com.securelink.app.vpn.VpnEngine
import com.securelink.app.vpn.VpnLog

/**
 * صفحه اصلی: لیست پروفایل‌ها با امکان اتصال/قطع و ویرایش.
 */
class ProfilesFragment : Fragment() {

    private var _binding: FragmentProfilesBinding? = null
    private val binding get() = _binding!!

    private lateinit var adapter: ProfileAdapter

    /** پروفایلی که در انتظار تأیید مجوز VPN است (WireGuard یا IKEv2) */
    private var pendingProfileId: String? = null

    private val consentLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val profile = ProfileStore.findById(pendingProfileId)
            pendingProfileId = null
            if (result.resultCode == Activity.RESULT_OK && profile != null) {
                when (profile.type) {
                    ProfileType.WIREGUARD -> connectWireGuardNow(profile)
                    ProfileType.IKEV2 -> startIkev2Now(profile)
                    ProfileType.L2TP -> connectL2tpNow(profile)
                }
            } else {
                toast(R.string.perm_vpn_needed)
            }
        }

    private val engineListener: () -> Unit = {
        if (isAdded) {
            adapter.notifyDataSetChanged()
            maybeShowL2tpErrorToast()
        }
    }

    /** زمانِ آخرین خطای قطع‌شدنی که به کاربر نشان داده شد */
    private var lastErrorShownAt = 0L

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentProfilesBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        adapter = ProfileAdapter(
            isConnected = { profile -> isProfileConnected(profile) },
            onToggle = { profile -> toggleProfile(profile) },
            onEdit = { profile -> openEditor(profile.id) }
        )
        binding.rvProfiles.layoutManager = LinearLayoutManager(requireContext())
        binding.rvProfiles.adapter = adapter

        binding.fabAdd.setOnClickListener { openEditor(null) }
        binding.btnDiagnostics.setOnClickListener { openDiagnostics() }

        refreshList()
    }

    override fun onStart() {
        super.onStart()
        VpnEngine.addListener(engineListener)
    }

    override fun onStop() {
        super.onStop()
        VpnEngine.removeListener(engineListener)
    }

    override fun onResume() {
        super.onResume()
        refreshList()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    // ------------------------------------------------------------------

    private fun refreshList() {
        (requireActivity() as? androidx.appcompat.app.AppCompatActivity)
            ?.supportActionBar?.title = getString(R.string.profiles_title)
        adapter.submit(ProfileStore.profiles)
        val empty = ProfileStore.profiles.isEmpty()
        binding.tvEmpty.visibility = if (empty) View.VISIBLE else View.GONE
        binding.rvProfiles.visibility = if (empty) View.GONE else View.VISIBLE
    }

    private fun isProfileConnected(profile: VpnProfile): Boolean = when (profile.type) {
        ProfileType.WIREGUARD -> VpnEngine.isWireGuardRunning(requireContext(), profile)
        ProfileType.IKEV2 -> VpnEngine.isIkev2Active(profile.id)
        ProfileType.L2TP -> VpnEngine.isL2tpActive(profile.id)
    }

    private fun toggleProfile(profile: VpnProfile) {
        if (isProfileConnected(profile)) {
            when (profile.type) {
                ProfileType.WIREGUARD ->
                    VpnEngine.disconnectWireGuard(requireContext(), profile) { ok, err ->
                        showResult(ok, err, R.string.disconnect_success, R.string.connect_failed)
                    }
                ProfileType.IKEV2 ->
                    VpnEngine.stopIkev2(requireContext()) { ok, err ->
                        showResult(ok, err, R.string.disconnect_success, R.string.connect_failed)
                    }
                ProfileType.L2TP -> {
                    VpnEngine.stopL2tp(requireContext())
                    toast(R.string.disconnect_success)
                }
            }
        } else {
            when (profile.type) {
                ProfileType.WIREGUARD -> requestConsentAndConnectWireGuard(profile)
                ProfileType.IKEV2 -> requestConsentAndConnectIkev2(profile)
                ProfileType.L2TP -> requestConsentAndConnectL2tp(profile)
            }
        }
    }

    // ---- WireGuard ----

    private fun requestConsentAndConnectWireGuard(profile: VpnProfile) {
        val intent = VpnEngine.prepareWireGuardPermission(requireContext())
        if (intent != null) {
            pendingProfileId = profile.id
            consentLauncher.launch(intent)
        } else {
            connectWireGuardNow(profile)
        }
    }

    private fun connectWireGuardNow(profile: VpnProfile) {
        VpnEngine.connectWireGuard(requireContext(), profile) { ok, err ->
            showResult(ok, err, R.string.connect_success, R.string.connect_failed)
        }
    }

    // ---- IKEv2 / IPSec ----

    private fun requestConsentAndConnectIkev2(profile: VpnProfile) {
        if (!VpnEngine.isIkev2Supported) {
            toast(R.string.ikev2_unsupported)
            return
        }
        try {
            val intent = VpnEngine.provisionIkev2(requireContext(), profile)
            if (intent != null) {
                pendingProfileId = profile.id
                consentLauncher.launch(intent)
            } else {
                startIkev2Now(profile)
            }
        } catch (t: Throwable) {
            toast(R.string.connect_failed, t.message)
        }
    }

    private fun startIkev2Now(profile: VpnProfile) {
        VpnEngine.startIkev2(requireContext(), profile) { ok, err ->
            showResult(ok, err, R.string.connect_success, R.string.connect_failed)
        }
    }

    // ---- L2TP / PPP ----

    private fun requestConsentAndConnectL2tp(profile: VpnProfile) {
        val intent = VpnEngine.prepareL2tpPermission(requireContext())
        if (intent != null) {
            pendingProfileId = profile.id
            consentLauncher.launch(intent)
        } else {
            connectL2tpNow(profile)
        }
    }

    private fun connectL2tpNow(profile: VpnProfile) {
        VpnEngine.connectL2tp(requireContext(), profile)
        toast(R.string.l2tp_connecting)
    }

    // ---- ناوبری ----

    private fun openEditor(profileId: String?) {
        val fragment = EditProfileFragment().apply {
            arguments = Bundle().apply { putString(EditProfileFragment.ARG_PROFILE_ID, profileId) }
        }
        parentFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, fragment)
            .addToBackStack(null)
            .commit()
    }

    private fun openDiagnostics() {
        parentFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, LogFragment())
            .addToBackStack(null)
            .commit()
    }

    /**
     * اگر اتصال L2TP خودسرانه قطع شده باشد، علت را به کاربر نشان می‌دهیم.
     * قطعی که خود کاربر از همین صفحه زده را نشان نمی‌دهیم (چون توست موفقیت دیده می‌شود).
     */
    private fun maybeShowL2tpErrorToast() {
        val at = VpnLog.lastL2tpErrorAt
        if (at == 0L || at <= lastErrorShownAt) return
        lastErrorShownAt = at
        val err = VpnLog.lastL2tpError ?: return
        if (err == L2tpVpnService.REASON_USER_DISCONNECT) return
        Toast.makeText(
            requireContext(),
            getString(R.string.l2tp_disconnected_toast, err),
            Toast.LENGTH_LONG
        ).show()
    }

    // ---- ابزار ----

    private fun showResult(ok: Boolean, err: String?, successRes: Int, failRes: Int) {
        if (!isAdded) return
        if (ok) toast(successRes)
        else toast(failRes, err)
    }

    private fun toast(resId: Int, extra: String? = null) {
        if (!isAdded) return
        val text = getString(resId) + (extra?.let { "\n$it" } ?: "")
        Toast.makeText(requireContext(), text, Toast.LENGTH_LONG).show()
    }
}
