package com.securelink.app.ui

import android.annotation.SuppressLint
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import com.securelink.app.R
import com.securelink.app.data.IkeAuthType
import com.securelink.app.data.ProfileStore
import com.securelink.app.data.ProfileType
import com.securelink.app.data.VpnProfile
import com.securelink.app.databinding.FragmentEditProfileBinding
import com.securelink.app.vpn.VpnEngine

/**
 * فرم افزودن/ویرایش پروفایل؛ بسته به نوع پروتکل، بخش مربوطه نمایش داده می‌شود.
 */
class EditProfileFragment : Fragment() {

    companion object {
        const val ARG_PROFILE_ID = "profileId"
    }

    private var _binding: FragmentEditProfileBinding? = null
    private val binding get() = _binding!!

    private var editingProfile: VpnProfile? = null
    private var selectedType: ProfileType = ProfileType.WIREGUARD
    private var selectedAuth: IkeAuthType = IkeAuthType.USERNAME_PASSWORD

    private val importLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) importWireGuardConfig(uri)
        }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentEditProfileBinding.inflate(inflater, container, false)
        return binding.root
    }

    @SuppressLint("Range")
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val profileId = arguments?.getString(ARG_PROFILE_ID)
        editingProfile = ProfileStore.findById(profileId)

        setupTypeSpinner()
        setupAuthSpinner()
        setupButtons()

        editingProfile?.let { fillForm(it) } ?: updateSections()

        (requireActivity() as? androidx.appcompat.app.AppCompatActivity)?.supportActionBar?.title =
            if (editingProfile == null) getString(R.string.edit_title_new)
            else getString(R.string.edit_title_edit)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    // ------------------------------------------------------------------

    private fun setupTypeSpinner() {
        val labels = arrayOf(
            getString(R.string.type_wireguard),
            getString(R.string.type_ikev2),
            getString(R.string.type_l2tp)
        )
        binding.spinnerType.adapter = ArrayAdapter(
            requireContext(), android.R.layout.simple_spinner_dropdown_item, labels
        )
        binding.spinnerType.setSelection(
            when (selectedType) {
                ProfileType.WIREGUARD -> 0
                ProfileType.IKEV2 -> 1
                ProfileType.L2TP -> 2
            }
        )
        binding.spinnerType.onItemSelectedListener =
            object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(
                    parent: android.widget.AdapterView<*>?,
                    v: View?, position: Int, id: Long
                ) {
                    selectedType = when (position) {
                        1 -> ProfileType.IKEV2
                        2 -> ProfileType.L2TP
                        else -> ProfileType.WIREGUARD
                    }
                    updateSections()
                }

                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }
    }

    private fun setupAuthSpinner() {
        val labels = arrayOf(
            getString(R.string.auth_userpass),
            getString(R.string.auth_psk)
        )
        binding.spinnerAuthType.adapter = ArrayAdapter(
            requireContext(), android.R.layout.simple_spinner_dropdown_item, labels
        )
        binding.spinnerAuthType.setSelection(if (selectedAuth == IkeAuthType.USERNAME_PASSWORD) 0 else 1)
        binding.spinnerAuthType.onItemSelectedListener =
            object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onItemSelected(
                    parent: android.widget.AdapterView<*>?,
                    v: View?, position: Int, id: Long
                ) {
                    selectedAuth =
                        if (position == 0) IkeAuthType.USERNAME_PASSWORD else IkeAuthType.PSK
                    updateAuthSections()
                }

                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
            }
    }

    private fun setupButtons() {
        binding.btnImport.setOnClickListener {
            importLauncher.launch(arrayOf("*/*"))
        }
        binding.btnSave.setOnClickListener { save() }
        binding.btnDelete.setOnClickListener { confirmDelete() }
        binding.btnDelete.visibility =
            if (editingProfile == null) View.GONE else View.VISIBLE
    }

    private fun fillForm(profile: VpnProfile) {
        binding.etName.setText(profile.name)

        when (profile.type) {
            ProfileType.WIREGUARD -> {
                selectedType = ProfileType.WIREGUARD
                binding.spinnerType.setSelection(0)
                binding.etWgConfig.setText(profile.wgConfigText)
            }
            ProfileType.IKEV2 -> {
                selectedType = ProfileType.IKEV2
                binding.spinnerType.setSelection(1)
                binding.etIkeServer.setText(profile.ikeServer)
                binding.etIkeIdentity.setText(profile.ikeIdentity)
                selectedAuth = profile.ikeAuthType
                binding.spinnerAuthType.setSelection(
                    if (profile.ikeAuthType == IkeAuthType.USERNAME_PASSWORD) 0 else 1
                )
                binding.etIkeUsername.setText(profile.ikeUsername)
                binding.etIkePassword.setText(profile.ikePassword)
                binding.etIkePsk.setText(profile.ikePsk)
            }
            ProfileType.L2TP -> {
                selectedType = ProfileType.L2TP
                binding.spinnerType.setSelection(2)
                binding.etL2tpServer.setText(profile.l2tpServer)
                binding.etL2tpUsername.setText(profile.l2tpUsername)
                binding.etL2tpPassword.setText(profile.l2tpPassword)
                binding.etL2tpSecret.setText(profile.l2tpSecret)
            }
        }
        updateSections()
    }

    private fun updateSections() {
        binding.sectionWireguard.visibility =
            if (selectedType == ProfileType.WIREGUARD) View.VISIBLE else View.GONE
        binding.sectionIkev2.visibility =
            if (selectedType == ProfileType.IKEV2) View.VISIBLE else View.GONE
        binding.sectionL2tp.visibility =
            if (selectedType == ProfileType.L2TP) View.VISIBLE else View.GONE
        updateAuthSections()
    }

    private fun updateAuthSections() {
        val userPass = selectedAuth == IkeAuthType.USERNAME_PASSWORD
        binding.tilIkeUsername.visibility = if (userPass) View.VISIBLE else View.GONE
        binding.tilIkePassword.visibility = if (userPass) View.VISIBLE else View.GONE
        binding.tilIkePsk.visibility = if (userPass) View.GONE else View.VISIBLE
    }

    // ------------------------------------------------------------------

    private fun save() {
        val name = binding.etName.text?.toString()?.trim().orEmpty()
        if (name.isEmpty()) {
            binding.tilName.error = getString(R.string.err_name_required)
            return
        }
        binding.tilName.error = null

        val profile = editingProfile ?: VpnProfile().also { editingProfile = it }
        profile.name = name
        profile.type = selectedType

        if (selectedType == ProfileType.WIREGUARD) {
            val text = binding.etWgConfig.text?.toString()?.trim().orEmpty()
            val valid = text.contains("[Interface]", ignoreCase = true) &&
                    text.contains("PrivateKey", ignoreCase = true)
            if (!valid) {
                binding.tilWgConfig.error = getString(R.string.err_wg_config_invalid)
                return
            }
            binding.tilWgConfig.error = null
            profile.wgConfigText = text
        } else if (selectedType == ProfileType.L2TP) {
            val server = binding.etL2tpServer.text?.toString()?.trim().orEmpty()
            if (server.isEmpty()) {
                binding.tilL2tpServer.error = getString(R.string.err_ike_server_required)
                return
            }
            binding.tilL2tpServer.error = null
            val user = binding.etL2tpUsername.text?.toString()?.trim().orEmpty()
            val pass = binding.etL2tpPassword.text?.toString().orEmpty()
            if (user.isEmpty() || pass.isEmpty()) {
                binding.tilL2tpUsername.error = getString(R.string.err_ike_credentials)
                return
            }
            binding.tilL2tpUsername.error = null
            profile.l2tpServer = server
            profile.l2tpUsername = user
            profile.l2tpPassword = pass
            profile.l2tpSecret = binding.etL2tpSecret.text?.toString()?.trim().orEmpty()
        } else {
            val server = binding.etIkeServer.text?.toString()?.trim().orEmpty()
            if (server.isEmpty()) {
                binding.tilIkeServer.error = getString(R.string.err_ike_server_required)
                return
            }
            binding.tilIkeServer.error = null
            profile.ikeServer = server
            profile.ikeIdentity = binding.etIkeIdentity.text?.toString()?.trim().orEmpty()
            profile.ikeAuthType = selectedAuth
            when (selectedAuth) {
                IkeAuthType.USERNAME_PASSWORD -> {
                    val user = binding.etIkeUsername.text?.toString()?.trim().orEmpty()
                    val pass = binding.etIkePassword.text?.toString().orEmpty()
                    if (user.isEmpty() || pass.isEmpty()) {
                        binding.tilIkeUsername.error = getString(R.string.err_ike_credentials)
                        return
                    }
                    binding.tilIkeUsername.error = null
                    profile.ikeUsername = user
                    profile.ikePassword = pass
                }
                IkeAuthType.PSK -> {
                    val psk = binding.etIkePsk.text?.toString().orEmpty()
                    if (psk.isEmpty()) {
                        binding.tilIkePsk.error = getString(R.string.err_ike_psk)
                        return
                    }
                    binding.tilIkePsk.error = null
                    profile.ikePsk = psk
                }
            }
        }

        val isNew = ProfileStore.findById(profile.id) == null
        if (isNew) ProfileStore.add(profile, requireContext())
        else ProfileStore.update(requireContext())

        parentFragmentManager.popBackStack()
    }

    private fun confirmDelete() {
        val profile = editingProfile ?: return
        com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.delete_confirm_title)
            .setMessage(R.string.delete_confirm_message)
            .setPositiveButton(R.string.delete) { _, _ ->
                // اگر تانل این پروفایل در حال اجراست، ابتدا قطع شود
                if (profile.type == ProfileType.WIREGUARD &&
                    VpnEngine.isWireGuardRunning(requireContext(), profile)
                ) {
                    VpnEngine.disconnectWireGuard(requireContext(), profile) { _, _ -> }
                } else if (profile.type == ProfileType.IKEV2 &&
                    VpnEngine.isIkev2Active(profile.id)
                ) {
                    VpnEngine.stopIkev2(requireContext()) { _, _ -> }
                } else if (profile.type == ProfileType.L2TP &&
                    VpnEngine.isL2tpActive(profile.id)
                ) {
                    VpnEngine.stopL2tp(requireContext())
                }
                ProfileStore.remove(profile.id, requireContext())
                parentFragmentManager.popBackStack()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    // ------------------------------------------------------------------

    private fun importWireGuardConfig(uri: Uri) {
        try {
            val text = requireContext().contentResolver.openInputStream(uri)?.use { stream ->
                stream.bufferedReader().readText()
            } ?: return

            if (selectedType != ProfileType.WIREGUARD) {
                selectedType = ProfileType.WIREGUARD
                binding.spinnerType.setSelection(0)
            }
            binding.etWgConfig.setText(text)

            val fileName = queryDisplayName(uri)
            val suggested = fileName
                ?.removeSuffix(".conf")?.removeSuffix(".Conf")?.removeSuffix(".CONF")
                ?.takeIf { it.isNotBlank() }
            if (binding.etName.text.isNullOrBlank() && suggested != null) {
                binding.etName.setText(suggested)
            }
        } catch (t: Throwable) {
            Toast.makeText(requireContext(), R.string.file_read_failed, Toast.LENGTH_SHORT).show()
        }
    }

    private fun queryDisplayName(uri: Uri): String? {
        var cursor: Cursor? = null
        return try {
            cursor = requireContext().contentResolver.query(
                uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null
            )
            cursor?.moveToFirst()
            cursor?.getString(0)
        } catch (_: Exception) {
            null
        } finally {
            cursor?.close()
        }
    }
}
