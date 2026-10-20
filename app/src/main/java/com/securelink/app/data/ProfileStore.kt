package com.securelink.app.data

import android.content.Context
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * ذخیره‌سازی ساده و مطمئن پروفایل‌ها به‌صورت JSON در حافظه داخلی برنامه.
 * Gson به‌صورت پیش‌فرض enum ها را با نامشان ذخیره/بازیابی می‌کند.
 */
object ProfileStore {

    private const val FILE_NAME = "securelink_profiles.json"

    private val gson = Gson()
    private val listType = object : TypeToken<MutableList<VpnProfile>>() {}.type

    val profiles: MutableList<VpnProfile> = mutableListOf()

    fun load(context: Context) {
        try {
            val file = context.applicationContext.getFileStreamPath(FILE_NAME)
            if (file.exists()) {
                context.applicationContext.openFileInput(FILE_NAME).use { input ->
                    val json = input.bufferedReader().readText()
                    val loaded: MutableList<VpnProfile> =
                        gson.fromJson(json, listType) ?: mutableListOf()
                    profiles.clear()
                    profiles.addAll(loaded)
                }
            }
        } catch (_: Exception) {
            // در صورت خرابی فایل، لیست خالی شروع می‌شود تا برنامه کرش نکند
            profiles.clear()
        }
    }

    @Synchronized
    fun save(context: Context) {
        try {
            context.applicationContext.openFileOutput(FILE_NAME, Context.MODE_PRIVATE).use { out ->
                out.write(gson.toJson(profiles).toByteArray(Charsets.UTF_8))
            }
        } catch (_: Exception) {
            // ذخیره‌سازی نباید باعث کرش شود
        }
    }

    fun findById(id: String?): VpnProfile? = profiles.firstOrNull { it.id == id }

    fun add(profile: VpnProfile, context: Context) {
        profiles.add(profile)
        save(context)
    }

    fun update(context: Context) {
        save(context)
    }

    fun remove(id: String, context: Context): Boolean {
        val removed = profiles.removeAll { it.id == id }
        if (removed) save(context)
        return removed
    }
}
