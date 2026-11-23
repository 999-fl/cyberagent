package com.cyberagent.mobile

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext

object NetTools {
 private val ports = listOf(21 to "FTP",22 to "SSH",23 to "Telnet",25 to "SMTP",53 to "DNS",80 to "HTTP",110 to "POP3",139 to "NetBIOS",143 to "IMAP",445 to "SMB",554 to "RTSP",631 to "IPP",443 to "HTTPS",8080 to "HTTP-alt",8443 to "HTTPS-alt",9000 to "Common-alt",3389 to "RDP")
 suspend fun scan(host:String):String = withContext(Dispatchers.IO) {
  return@withContext scan(host,1,65535)
 }
 suspend fun scan(host:String,startPort:Int,endPort:Int):String = withContext(Dispatchers.IO) {
  val h=cleanHost(host)
  val start=startPort.coerceIn(1,65535)
  val end=endPort.coerceIn(start,65535)
  val results=(start..end).chunked(256).flatMap { chunk ->
   chunk.map { port -> async(Dispatchers.IO) { try { Socket().use { s -> s.connect(java.net.InetSocketAddress(h,port),650); "OPEN $port${knownService(port)}" } } catch (_:Exception){ null } } }.awaitAll().filterNotNull()
  }
  val out=StringBuilder("TCP connect scan of $h ($start-$end):\n")
  if(results.isEmpty()) out.append("No common TCP ports reachable (or scan blocked).") else results.forEach { out.append(it).append('\n') }
  out.toString()
 }
 suspend fun dns(host:String):String = withContext(Dispatchers.IO) {
  val h=cleanHost(host)
  try { InetAddress.getAllByName(h).joinToString("\n") { "$h → ${it.hostAddress}" } } catch(e:Exception) { "DNS error: ${e.message}" }
 }
 suspend fun http(raw:String):String = http(raw,cleanHost(raw))
 suspend fun http(raw:String,allowedHost:String):String = withContext<String>(Dispatchers.IO) {
  try {
   var url=if(raw.startsWith("http://")||raw.startsWith("https://")) raw else "https://$raw"; val visited=mutableListOf<String>()
   while(true) {
    if(url in visited) return@withContext "Redirect loop detected:\n"+visited.joinToString(" → ")
    visited.add(url)
    val c=URL(url).openConnection() as HttpURLConnection; c.connectTimeout=7000;c.readTimeout=7000;c.instanceFollowRedirects=false;c.requestMethod="GET";c.setRequestProperty("User-Agent","CyberAgent-Android/0.2")
    val status=c.responseCode; val headerMap=c.headerFields.filterKeys{it!=null}; val headers=headerMap.entries.joinToString("\n"){ "${it.key}: ${it.value.joinToString()}" }
    val location=c.getHeaderField("Location"); val tls=if(c is HttpsURLConnection) "TLS cipher: ${c.cipherSuite}" else "Plain HTTP (no TLS)"
    val checks=StringBuilder("\nSecurity-header review:\n")
    val required=listOf("Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","Referrer-Policy","Permissions-Policy")
    required.forEach { name -> if(headerMap.keys.any{it.equals(name,true)}) checks.append("PRESENT: $name\n") else checks.append("MISSING: $name\n") }
    headerMap.entries.firstOrNull { it.key.equals("Server",true) }?.let { checks.append("Server header: ${it.value.joinToString()}\n") }
    headerMap.entries.firstOrNull { it.key.equals("X-Powered-By",true) }?.let { checks.append("X-Powered-By: ${it.value.joinToString()}\n") }
    headerMap.entries.firstOrNull { it.key.equals("Content-Type",true) }?.let { checks.append("Content-Type: ${it.value.joinToString()}\n") }
    headerMap.entries.firstOrNull { it.key.equals("Access-Control-Allow-Origin",true) }?.let { checks.append("CORS ACAO: ${it.value.joinToString()}\n") }
    headerMap.entries.firstOrNull { it.key.equals("Cache-Control",true) }?.let { checks.append("Cache-Control: ${it.value.joinToString()}\n") }
    val cookies=headerMap.entries.filter{it.key.equals("Set-Cookie",true)}.flatMap{it.value}
    if(cookies.isEmpty()) checks.append("Cookies: no Set-Cookie headers observed.\n")
    cookies.forEachIndexed { index,cookie ->
     val parts=cookie.split(";").map{it.trim()}
     val flags=parts.drop(1).map{it.substringBefore("=").trim().lowercase()}.toSet()
     checks.append("Cookie ${index+1}: ${parts.firstOrNull()?.substringBefore("=")?.take(80) ?: "(unnamed)"}\n")
     listOf("secure","httponly","samesite").forEach { flag ->
      if(flag in flags) checks.append("  PRESENT: $flag\n") else checks.append("  MISSING: $flag\n")
     }
     parts.drop(1).filter{it.lowercase().startsWith("samesite=")}.forEach{checks.append("  $it\n")}
     if(url.startsWith("https://",true) && "secure" !in flags) checks.append("  REVIEW: HTTPS cookie lacks Secure\n")
     if("samesite" !in flags) checks.append("  REVIEW: cookie lacks SameSite\n")
    }
    val body=try { val stream=if(status>=400)c.errorStream else c.inputStream; stream?.bufferedReader()?.use{it.readText().take(200000)} ?: "" } catch(_:Exception){""}
    val forms=Regex("<form\\b[^>]*>",RegexOption.IGNORE_CASE).findAll(body).map{it.value}.toList()
    checks.append("Forms found: ${forms.size}\n")
    forms.take(10).forEachIndexed { i,form -> checks.append("Form ${i+1}: ${form.replace(Regex("\\s+")," ").take(400)}\n") }
    val inputs=Regex("<input\\b[^>]*>",RegexOption.IGNORE_CASE).findAll(body).map{it.value}.toList()
    checks.append("Input fields found: ${inputs.size}\n")
    inputs.take(25).forEach { tag -> val type=Regex("type=[\\\"']?([^\\\"'\\\\s>]+)",RegexOption.IGNORE_CASE).find(tag)?.groupValues?.get(1) ?: "text"; val name=Regex("name=[\\\"']?([^\\\"'\\\\s>]+)",RegexOption.IGNORE_CASE).find(tag)?.groupValues?.get(1) ?: "(unnamed)"; checks.append("Input: type=$type name=$name\\n") }
    val passwordFields=inputs.count { Regex("type=[\\\"']?password",RegexOption.IGNORE_CASE).containsMatchIn(it) }
    if(passwordFields>0) {
     checks.append("Passive form review: $passwordFields password field(s) detected.\\n")
     if(!url.startsWith("https://",true)) checks.append("WARNING: Password fields observed over non-HTTPS page URL. Verify secure transport before handling credentials.\\n")
     else checks.append("Note: Password fields observed on HTTPS; this alone does not establish form security.\\n")
    }
    forms.forEachIndexed { i,form ->
     val method=Regex("method=[\\\"']?([^\\\"'\\\\s>]+)",RegexOption.IGNORE_CASE).find(form)?.groupValues?.get(1)?.uppercase() ?: "GET"
     val action=Regex("action=[\\\"']?([^\\\"'\\\\s>]+)",RegexOption.IGNORE_CASE).find(form)?.groupValues?.get(1)
     checks.append("Form ${i+1}: method=${method ?: "GET"}")
     if(action!=null) checks.append(" action=$action")
     checks.append("\n")
     if(method=="GET" && passwordFields>0) checks.append("Review: form(s) use GET/default method while password fields are present; verify form association and ensure credentials are not placed in URLs.\n")
    }
    c.disconnect()
    if(status in 300..399 && !location.isNullOrBlank()) {
      val next=URL(URL(url),location).toString()
      url=next; continue
    }
    return@withContext "URL: $url\nStatus: $status\n$tls\nRedirect chain: ${visited.joinToString(" → ")}\nHeaders:\n$headers\n$checks"
   }
  } catch(e:Exception) { "Web inspection failed: ${e.message}" }
 }
  suspend fun wifi(context: Context):String = withContext(Dispatchers.IO) {
   val output=StringBuilder("Wi-Fi inventory:\n")
   val cm=context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
   val active=cm?.activeNetwork
   val caps=active?.let { cm.getNetworkCapabilities(it) }
   if(caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true) {
    output.append("Status: connected to Wi-Fi\n")
   } else if(caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)==true) {
    output.append("Status: connected to cellular; Wi-Fi inventory may be unavailable\n")
   } else {
    output.append("Status: no active Wi-Fi or cellular transport\n")
   }
   val wm=context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
   val info=wm?.connectionInfo
   if(info!=null) {
    val ssid=info.ssid?.removePrefix("\"")?.removeSuffix("\"")?.takeIf { it != "<unknown ssid>" } ?: "(hidden or permission restricted)"
    val bssid=info.bssid?.takeIf { it != "02:00:00:00:00:00" } ?: "(permission restricted)"
    output.append("SSID: $ssid\n")
    output.append("BSSID: $bssid\n")
    output.append("Link: ${info.linkSpeed} Mbps, RSSI ${info.rssi} dBm, frequency ${info.frequency} MHz\n")
    output.append("Local IP: ${intIp(info.ipAddress)}\n")
    val dhcp=wm.dhcpInfo
    output.append("Gateway: ${intIp(dhcp.gateway)}\n")
    output.append("Subnet: ${intIp(dhcp.netmask)}\n")
    output.append("DNS: ${intIp(dhcp.dns1)}, ${intIp(dhcp.dns2)}\n")
   }
   val visible=try { wm?.scanResults?.sortedByDescending { it.level }?.take(25) } catch (_:Exception){ null }
   if(visible.isNullOrEmpty()) {
    output.append("Nearby networks: unavailable. Location permission and Android Wi-Fi scan settings are required.\n")
   } else {
    output.append("Nearby networks:\n")
    visible.forEach { network ->
     val security=network.capabilities
      .takeIf { it.isNotBlank() }
      ?.split("]")
      ?.joinToString(" ")
      ?.replace("[","")
      ?.replace("]"," ")
      ?.trim()
      ?: "unknown"
     output.append("- ${network.SSID.ifBlank { "(hidden)" }} | ${network.level} dBm | ${network.frequency} MHz | $security\n")
    }
   }
   output.toString()
  }
  suspend fun tls(host:String,port:Int=443):String = withContext(Dispatchers.IO) {
   val h=cleanHost(host)
   if(port !in 1..65535) return@withContext "TLS inspection failed: invalid port."
   val socket=Socket()
   try {
    socket.connect(java.net.InetSocketAddress(h,port),7000)
    socket.soTimeout=7000
    val ssl=SSLContext.getDefault().socketFactory.createSocket(socket,h,port,true) as javax.net.ssl.SSLSocket
    ssl.use { sessionSocket ->
     sessionSocket.startHandshake()
     val session=sessionSocket.session
     val peer=session.peerCertificates.firstOrNull() as? X509Certificate
     val dateFormat=SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX",Locale.US)
     val out=StringBuilder("TLS inspection of $h:$port\n")
     out.append("Protocol: ${session.protocol}\n")
     out.append("Cipher suite: ${session.cipherSuite}\n")
     if(peer==null) {
      out.append("Peer certificate: unavailable\n")
     } else {
      out.append("Certificate subject: ${peer.subjectX500Principal.name}\n")
      out.append("Certificate issuer: ${peer.issuerX500Principal.name}\n")
      out.append("Certificate valid from: ${dateFormat.format(peer.notBefore)}\n")
      out.append("Certificate valid until: ${dateFormat.format(peer.notAfter)}\n")
      val now=System.currentTimeMillis()
      if(now < peer.notBefore.time) out.append("Certificate review: NOT YET VALID\n")
      else if(now > peer.notAfter.time) out.append("Certificate review: EXPIRED\n")
      else out.append("Certificate review: currently within validity period\n")
      out.append("Certificate SHA-256: ${peer.encodedSha256()}\n")
      out.append("SANs: ${peer.subjectAlternativeNames?.flattenStrings().orEmpty().ifBlank { "(none reported)" }}\n")
     }
     out.toString()
    }
   } catch(e:Exception) {
    "TLS inspection failed for $h:$port: ${e.message}"
   } finally {
    socket.close()
   }
  }
  private fun X509Certificate.encodedSha256():String {
   val digest=java.security.MessageDigest.getInstance("SHA-256").digest(encoded)
   return digest.joinToString("") { "%02X".format(it) }
  }
  private fun Collection<List<*>>.flattenStrings():String=flatMap { it.drop(1) }.map { it.toString() }.distinct().joinToString(", ")
  private fun intIp(value:Int):String {
   if(value==0) return "(none)"
   return "${value and 0xff}.${value shr 8 and 0xff}.${value shr 16 and 0xff}.${value shr 24 and 0xff}"
  }
  private fun knownService(port:Int):String=ports.firstOrNull{it.first==port}?.let{ " (${it.second})" } ?: ""
 private fun cleanHost(raw:String)=try { URL(if(raw.startsWith("http"))raw else "https://$raw").host.lowercase().removePrefix("www.") } catch(_:Exception) { raw.trim().removePrefix("http://").removePrefix("https://").substringBefore("/").substringBefore(":").lowercase().removePrefix("www.") }
}