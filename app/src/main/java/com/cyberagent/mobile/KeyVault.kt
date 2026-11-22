package com.cyberagent.mobile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Android Keystore-backed storage for provider credentials. */
object KeyVault {
 private const val STORE = "cyberagent_secure"
 private const val ENTRY = "api_key"
 private const val KEY_ALIAS = "CyberAgentApiKey"
 private const val ANDROID_KEYSTORE = "AndroidKeyStore"
 private const val TRANSFORMATION = "AES/GCM/NoPadding"

 private fun key(): SecretKey {
  val ks=KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
  (ks.getKey(KEY_ALIAS,null) as? SecretKey)?.let{return it}
  val generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,ANDROID_KEYSTORE)
  generator.init(KeyGenParameterSpec.Builder(KEY_ALIAS,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
   .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
  return generator.generateKey()
 }
 fun save(context:Context,value:String) {
  if(value.isBlank()){clear(context);return}
  val cipher=Cipher.getInstance(TRANSFORMATION);cipher.init(Cipher.ENCRYPT_MODE,key())
  val encrypted=cipher.doFinal(value.toByteArray(Charsets.UTF_8))
  val encoded=Base64.encodeToString(cipher.iv,Base64.NO_WRAP)+"."+Base64.encodeToString(encrypted,Base64.NO_WRAP)
  context.getSharedPreferences(STORE,Context.MODE_PRIVATE).edit().putString(ENTRY,encoded).apply()
 }
 fun load(context:Context):String {
  val stored=context.getSharedPreferences(STORE,Context.MODE_PRIVATE).getString(ENTRY,null) ?: return ""
  return try {
   val parts=stored.split(".",limit=2);if(parts.size!=2)return ""
   val iv=Base64.decode(parts[0],Base64.NO_WRAP);val bytes=Base64.decode(parts[1],Base64.NO_WRAP)
   val cipher=Cipher.getInstance(TRANSFORMATION);cipher.init(Cipher.DECRYPT_MODE,key(),GCMParameterSpec(128,iv))
   String(cipher.doFinal(bytes),Charsets.UTF_8)
  }catch(_:Exception){clear(context);""}
 }
 fun clear(context:Context){context.getSharedPreferences(STORE,Context.MODE_PRIVATE).edit().remove(ENTRY).apply()}
}