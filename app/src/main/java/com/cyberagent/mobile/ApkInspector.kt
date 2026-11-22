package com.cyberagent.mobile

import android.content.Context
import android.net.Uri
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

object ApkInspector {
 fun inspect(context:Context,uri:Uri):String {
  val file=File(context.cacheDir,"inspect-"+System.currentTimeMillis()+".apk")
  try {
   context.contentResolver.openInputStream(uri)?.use { input -> file.outputStream().use { output -> input.copyTo(output) } } ?: return "Could not read APK."
   val info=if(Build.VERSION.SDK_INT>=33) context.packageManager.getPackageArchiveInfo(file.absolutePath,PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())) else context.packageManager.getPackageArchiveInfo(file.absolutePath,PackageManager.GET_PERMISSIONS)
   if(info==null)return "APK metadata could not be parsed."
   val app=info.applicationInfo ?: return "APK has no application metadata."
   app.sourceDir=file.absolutePath; app.publicSourceDir=file.absolutePath
   val label=try{context.packageManager.getApplicationLabel(app).toString()}catch(_:Exception){ "(unknown)"}
   val permissions=info.requestedPermissions ?: emptyArray()
   val risky=permissions.filter { it.contains("SMS")||it.contains("CALL")||it.contains("LOCATION")||it.contains("RECORD_AUDIO")||it.contains("CAMERA")||it.contains("CONTACTS")||it.contains("READ_EXTERNAL_STORAGE")||it.contains("WRITE_EXTERNAL_STORAGE")||it.contains("MANAGE_EXTERNAL_STORAGE")||it.contains("QUERY_ALL_PACKAGES")||it.contains("SYSTEM_ALERT_WINDOW")||it.contains("ACCESSIBILITY")||it.contains("INSTALL_PACKAGES")||it.contains("REQUEST_INSTALL_PACKAGES") }
   return buildString {
    appendLine("APK metadata inspection (static metadata only)")
    appendLine("App: "+label);appendLine("Package: "+info.packageName);appendLine("Version: "+(info.versionName ?: "(unknown)"));appendLine("SDK target: "+app.targetSdkVersion)
    appendLine("Requested permissions: "+permissions.size)
    permissions.sorted().forEach{appendLine(" • "+it)}
    appendLine("\nPermissions worth reviewing: "+risky.size)
    risky.sorted().forEach{appendLine(" ! "+it)}
    appendLine("\nThis is a permissions inventory, not a malware verdict.")
   }
  }catch(e:Exception){ "APK inspection error: "+e.message }finally{file.delete()}
 }
}
