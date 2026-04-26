# ──────────────────────────────────────────────────────────────────────────────
# AdBlocker ProGuard / R8 rules
# ──────────────────────────────────────────────────────────────────────────────

# ── BouncyCastle ──────────────────────────────────────────────────────────────
# Весь BC нужен для MITM: генерация CA, подпись сертификатов, TLS.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# ── OkHttp / Okio ─────────────────────────────────────────────────────────────
# OkHttp используется только если DomainListUpdater переключится на него.
# Пока используем HttpURLConnection, но оставляем правило на случай обновления.
-keep class okhttp3.** { *; }
-dontwarn okhttp3.**
-keep class okio.** { *; }
-dontwarn okio.**

# ── Gson ──────────────────────────────────────────────────────────────────────
# Gson используется для YouTube JSON фильтрации в AdFilter.
-keep class com.google.gson.** { *; }
-dontwarn com.google.gson.**
# Gson использует reflection — не трогаем поля data-классов
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# ── Room ──────────────────────────────────────────────────────────────────────
-keep class * extends androidx.room.RoomDatabase { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao interface * { *; }
-keep class * extends androidx.room.migration.Migration { *; }

# ── Kotlin coroutines ─────────────────────────────────────────────────────────
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}

# ── Our core classes — никогда не обфусцировать ───────────────────────────────
-keep class com.adblocker.** { *; }

# ── Общие правила ─────────────────────────────────────────────────────────────
# Сохраняем имена для stack trace в логах
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Аннотации Kotlin
-keepattributes RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations

# VpnService — системный компонент, не трогать
-keep class * extends android.net.VpnService { *; }

# BroadcastReceiver
-keep class * extends android.content.BroadcastReceiver { *; }

# Warnings подавляем только для известных safe-deps
-dontwarn java.lang.invoke.**
-dontwarn javax.annotation.**
