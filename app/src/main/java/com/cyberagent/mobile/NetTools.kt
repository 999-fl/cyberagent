package com.cyberagent.mobile

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.InetAddress
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.io.File
import java.net.URLEncoder
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext

object NetTools {
 private val ports = listOf(21 to "FTP",22 to "SSH",23 to "Telnet",25 to "SMTP",53 to "DNS",80 to "HTTP",110 to "POP3",139 to "NetBIOS",143 to "IMAP",445 to "SMB",554 to "RTSP",631 to "IPP",443 to "HTTPS",8080 to "HTTP-alt",8443 to "HTTPS-alt",9000 to "Common-alt",3389 to "RDP")
 suspend fun scan(host:String):String = withContext(Dispatchers.IO) {
  val h=cleanHost(host)
  val portList=ports.map { it.first }
  scanPorts(h,portList,250)
 }
 suspend fun scan(host:String,startPort:Int,endPort:Int):String = withContext(Dispatchers.IO) {
  val h=cleanHost(host)
  val start=startPort.coerceIn(1,65535)
  val end=endPort.coerceIn(start,65535)
  val output=StringBuilder("TCP connect scan of $h ($start-$end):\n")
  var openCount=0
  (start..end).chunked(512).forEach { batch ->
   val result=scanPorts(h,batch,250)
   val openLines=result.lineSequence().filter { it.startsWith("OPEN ") }
   openLines.forEach { output.append("$it\n"); openCount++ }
  }
  if(openCount==0) output.append("No tested ports reachable.")
  output.toString()
 }
 private suspend fun scanPorts(host:String,portList:List<Int>,timeoutMs:Int):String=coroutineScope {
  val semaphore=Semaphore(24)
  val results=portList.map { port ->
   async(Dispatchers.IO) {
    ensureActive()
    semaphore.withPermit {
     try {
      Socket().use { socket ->
       socket.connect(java.net.InetSocketAddress(host,port),timeoutMs)
       "OPEN $port${knownService(port)}"
      }
     } catch (_:Exception) { null }
    }
   }
  }.awaitAll().filterNotNull()
  val out=StringBuilder("TCP connect scan of $host (${portList.size} ports):\n")
  if(results.isEmpty()) out.append("No tested ports reachable.") else results.forEach { out.append(it).append('\n') }
  out.toString()
 }
 suspend fun activePhpValidation(raw:String):String=withContext(Dispatchers.IO) {
  val base=if(raw.startsWith("http://")||raw.startsWith("https://")) raw.trimEnd('/') else "https://$raw"
  val urlBase=try { URL(base).let { URL(it.protocol,it.host,it.port.takeIf { p -> p!=-1 } ?: -1,"/").toString().trimEnd('/') } } catch(_:Exception){ base }
  val out=StringBuilder("Active PHP/application validation for $urlBase\n")
  val checks=listOf(
   "/wp-json/" to "WordPress REST API",
   "/wp-json/wp/v2/users" to "WordPress REST user enumeration",
   "/wp-content/debug.log" to "WordPress debug log",
   "/wp-content/uploads/" to "Upload directory listing",
   "/phpinfo.php" to "PHP diagnostic endpoint",
   "/server-status" to "Server status endpoint",
   "/.env" to "Environment file",
   "/.git/config" to "Git configuration",
   "/wp-config.php.bak" to "WordPress backup",
   "/backup.zip" to "Backup archive"
  )
  var confirmed=0
  for((path,label) in checks) {
   try {
    val c=URL(urlBase+path).openConnection() as HttpURLConnection
    c.connectTimeout=3500;c.readTimeout=3500;c.instanceFollowRedirects=false;c.requestMethod="GET"
    c.setRequestProperty("User-Agent","CyberAgent-Active/0.1")
    val status=c.responseCode
    val body=try {
     val stream=if(status>=400)c.errorStream else c.inputStream
     stream?.bufferedReader()?.use { it.readText().take(48000) } ?: ""
    } catch(_:Exception){""}
    val lower=body.lowercase()
    val marker=when(path) {
     "/wp-json/" -> lower.contains("\"namespaces\"")||lower.contains("\"routes\"")
     "/wp-json/wp/v2/users" -> lower.startsWith("[")&&lower.contains("\"slug\"")&&lower.contains("\"name\"")
     "/wp-content/debug.log" -> status==200&&lower.contains("php ")&&lower.contains("stack")
     "/wp-content/uploads/" -> lower.contains("index of")||lower.contains("parent directory")
     "/phpinfo.php" -> lower.contains("php version")||lower.contains("phpinfo")
     "/server-status" -> lower.contains("apache server status")||lower.contains("server uptime")
     "/.env" -> lower.contains("app_")||lower.contains("db_")||lower.contains("password")||lower.contains("secret")
     "/.git/config" -> lower.contains("[core]")||lower.contains("repositoryformat")
     "/wp-config.php.bak","/backup.zip" -> status==200&&body.length>32
     else -> false
    }
    val verdict=if(marker) "CONFIRMED $label"
     else if(status in 200..299) "ACCESSIBLE; SENSITIVE CONTENT NOT CONFIRMED"
     else if(status==401||status==403) "AUTHORIZATION REQUIRED"
     else if(status in 300..399) "REDIRECT"
     else if(status==404) "NOT FOUND"
     else "HTTP $status"
    if(marker) confirmed++
    out.append("$path | HTTP $status | $verdict\n")
    if(marker) out.append("  Evidence: response markers matched $label\n")
    c.disconnect()
   } catch(e:Exception) {
    out.append("$path | INCONCLUSIVE | ${e.javaClass.simpleName}: ${e.message}\n")
   }
  }
  out.append("Confirmed active findings: $confirmed\n")
  out.append("This module uses only GET requests and does not send exploit payloads.\n")
  out.toString()
 }
 suspend fun testSuppliedCredentials(raw:String,username:String,password:String,basicAuth:Boolean):String=withContext(Dispatchers.IO) {
  if(username.isBlank()||password.isBlank()) return@withContext "Credential validation not run: username and password are both required."
  val base=if(raw.startsWith("http://")||raw.startsWith("https://")) raw.trimEnd('/') else "https://$raw"
  val urlBase=try { URL(base).let { URL(it.protocol,it.host,it.port.takeIf { p -> p!=-1 } ?: -1,"/").toString().trimEnd('/') } } catch(_:Exception){ base }
  if(basicAuth) {
   try {
    val c=URL(urlBase).openConnection() as HttpURLConnection
    c.connectTimeout=5000;c.readTimeout=5000;c.instanceFollowRedirects=false;c.requestMethod="GET"
    c.setRequestProperty("Authorization","Basic "+android.util.Base64.encodeToString("$username:$password".toByteArray(Charsets.UTF_8),android.util.Base64.NO_WRAP))
    c.setRequestProperty("User-Agent","CyberAgent-CredentialCheck/0.1")
    val status=c.responseCode
    val verdict=if(status in 200..299) "CONFIRMED SUPPLIED CREDENTIALS ACCEPTED"
     else if(status==401||status==403) "SUPPLIED CREDENTIALS REJECTED"
     else "INCONCLUSIVE HTTP $status"
    c.disconnect()
    return@withContext "HTTP Basic credential validation\n$verdict\nExact evidence: single GET returned HTTP $status.\nNo brute force or password guessing was performed."
   } catch(e:Exception) {
    return@withContext "HTTP Basic credential validation\nINCONCLUSIVE\nEvidence: ${e.javaClass.simpleName}: ${e.message}\nNo brute force or password guessing was performed."
   }
  }
  try {
   val loginUrl="$urlBase/wp-login.php"
   val c=URL(loginUrl).openConnection() as HttpURLConnection
   c.connectTimeout=5000;c.readTimeout=5000;c.instanceFollowRedirects=false;c.requestMethod="POST"
   c.doOutput=true;c.setRequestProperty("Content-Type","application/x-www-form-urlencoded")
   c.setRequestProperty("User-Agent","CyberAgent-CredentialCheck/0.1")
   val form=listOf(
    "log" to username,
    "pwd" to password,
    "wp-submit" to "Log In",
    "redirect_to" to "$urlBase/wp-admin/",
    "testcookie" to "1"
   ).joinToString("&") { (key,value) -> "${URLEncoder.encode(key,"UTF-8")}=${URLEncoder.encode(value,"UTF-8")}" }
   c.outputStream.use { it.write(form.toByteArray(Charsets.UTF_8)) }
   val status=c.responseCode
   val location=c.getHeaderField("Location").orEmpty()
   val cookies=c.headerFields.entries.filter { it.key?.equals("Set-Cookie",true)==true }.flatMap { it.value }.joinToString(";").lowercase()
   val body=try {
    val stream=if(status>=400)c.errorStream else c.inputStream
    stream?.bufferedReader()?.use { it.readText().take(12000) } ?: ""
   } catch(_:Exception){""}
   val success=cookies.contains("wordpress_logged_in") || location.contains("/wp-admin")
   val rejected=body.lowercase().contains("incorrect password")||body.lowercase().contains("invalid username")||body.lowercase().contains("unknown username")
   val verdict=if(success) "CONFIRMED SUPPLIED CREDENTIALS ACCEPTED"
    else if(rejected) "SUPPLIED CREDENTIALS REJECTED"
    else "INCONCLUSIVE"
   c.disconnect()
   "WordPress credential validation\n$verdict\nExact evidence: one POST returned HTTP $status.\nLocation: ${location.ifBlank { "(none)" }}\nLogin cookie observed: ${cookies.contains("wordpress_logged_in")}\nNo brute force or password guessing was performed."
  } catch(e:Exception) {
   "WordPress credential validation\nINCONCLUSIVE\nEvidence: ${e.javaClass.simpleName}: ${e.message}\nNo brute force or password guessing was performed."
  }
 }
 suspend fun validateTcp(host:String,port:Int):String = withContext(Dispatchers.IO) {
  val h=cleanHost(host)
  if(port !in 1..65535) return@withContext "VALIDATION INCONCLUSIVE: invalid TCP port."
  val socket=Socket()
  return@withContext try {
   socket.connect(java.net.InetSocketAddress(h,port),3000)
   socket.soTimeout=1500
   val banner=try {
    socket.getInputStream().readNBytes(1024).toString(Charsets.UTF_8)
     .replace(Regex("[^\\x20-\\x7E\\r\\n]"),".").take(1024)
   } catch (_:Exception){ "" }
   val out=StringBuilder("TCP validation of $h:$port\n")
   out.append("VERDICT: CONFIRMED REACHABLE\n")
   out.append("Confidence: high\n")
   out.append("Evidence: TCP connection completed successfully\n")
   if(banner.isNotBlank()) out.append("Banner: ${banner.replace('\n',' ').take(300)}\n")
   else out.append("Banner: unavailable until a protocol-specific request is sent\n")
   out.append("Vulnerability status: NOT PROVEN - open ports are connectivity findings, not vulnerabilities.\n")
   out.toString()
  } catch(e:Exception) {
   "TCP validation of $h:$port\nVERDICT: NOT REACHABLE\nConfidence: medium\nEvidence: ${e.javaClass.simpleName}: ${e.message}\nVulnerability status: NOT PROVEN"
  } finally {
   socket.close()
  }
 }
 suspend fun validateHttp(raw:String):String=withContext(Dispatchers.IO) {
  var base=if(raw.startsWith("http://")||raw.startsWith("https://")) raw.trimEnd('/') else "https://$raw"
  val urlBase=try { URL(base).let { URL(it.protocol,it.host,it.port.takeIf { p -> p!=-1 } ?: -1,"/").toString().trimEnd('/') } } catch(_:Exception){ base }
  val checks=listOf(
   "/wp-login.php" to "WordPress login surface",
   "/wp-admin/" to "WordPress admin surface",
   "/.env" to "Environment configuration exposure",
   "/.git/config" to "Git metadata exposure",
   "/phpinfo.php" to "PHP diagnostic page",
   "/server-status" to "Server status page",
   "/actuator" to "Spring actuator surface",
   "/swagger/index.html" to "API documentation",
   "/backup.zip" to "Backup archive exposure",
   "/wp-config.php.bak" to "WordPress configuration backup"
  )
  val out=StringBuilder("HTTP validation for $urlBase\n")
  var confirmed=0
  for((path,label) in checks) {
   try {
    val c=URL(urlBase+path).openConnection() as HttpURLConnection
    c.connectTimeout=3500;c.readTimeout=3500;c.instanceFollowRedirects=false;c.requestMethod="GET"
    c.setRequestProperty("User-Agent","CyberAgent-Android/0.3")
    val status=c.responseCode
    val body=try {
     val stream=if(status>=400)c.errorStream else c.inputStream
     stream?.bufferedReader()?.use { it.readText().take(32000) } ?: ""
    } catch(_:Exception){""}
    val lower=body.lowercase()
    val marker=when(path) {
     "/wp-login.php","/wp-admin/" -> lower.contains("wp-login")||lower.contains("wordpress")||lower.contains("log in")
     "/.env" -> lower.contains("app_")||lower.contains("db_")||lower.contains("secret")||lower.contains("password")
     "/.git/config" -> lower.contains("[core]")||lower.contains("repositoryformat")
     "/phpinfo.php" -> lower.contains("php version")||lower.contains("phpinfo")
     "/server-status" -> lower.contains("apache server status")||lower.contains("server uptime")
     "/actuator" -> lower.contains("\"_links\"")||lower.contains("\"status\"")
     "/swagger/index.html" -> lower.contains("swagger")||lower.contains("openapi")
     "/backup.zip","/wp-config.php.bak" -> status==200&&body.length>32
     else -> false
    }
    val verdict=if(status in 200..299 && marker) "CONFIRMED $label"
    else if(status in 200..299) "ACCESSIBLE BUT NOT CONFIRMED SENSITIVE"
    else if(status in 300..399) "REDIRECT RESPONSE"
    else if(status==401||status==403) "ACCESS REQUIRES AUTHORIZATION"
    else if(status==404) "NOT FOUND"
    else "HTTP $status"
    if(verdict.startsWith("CONFIRMED")) confirmed++
    out.append("$path | HTTP $status | $verdict\n")
    if(marker) out.append("  Evidence: response markers matched: $label\n")
    c.disconnect()
   } catch(e:Exception) {
    out.append("$path | VALIDATION INCONCLUSIVE | ${e.javaClass.simpleName}\n")
   }
  }
  out.append("Confirmed exposure count: $confirmed\n")
  out.append("Open status note: reachable services and HTTP 200 responses are not automatically vulnerabilities.\n")
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
   for (hop in 0 until Int.MAX_VALUE) {
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
   return@withContext "Redirect chain ended:\n${visited.joinToString(" → ")}"
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
  suspend fun arpAndRoutes():String = withContext(Dispatchers.IO) {
    val out=StringBuilder("Local kernel network table:\n")
    val arp=File("/proc/net/arp").takeIf { it.exists() }?.readText().orEmpty()
    val entries=arp.lines().drop(1).mapNotNull { line ->
     val fields=line.trim().split(Regex("\\s+"))
     if(fields.size>=6 && fields[0]!="IP address") {
      val ip=fields[0]; val mac=fields[3]; val flags=fields[2]
      if(mac!="00:00:00:00:00:00") "$ip  $mac  flags=$flags" else null
     } else null
    }
    out.append("ARP/neighbor entries:\n")
    if(entries.isEmpty()) out.append("(none exposed by Android kernel)\n") else entries.forEach { out.append("$it\n") }
    val routes=File("/proc/net/route").takeIf { it.exists() }?.readText().orEmpty()
    out.append("IPv4 routes:\n")
    routes.lines().drop(1).filter { it.isNotBlank() }.take(30).forEach { line ->
     val f=line.trim().split(Regex("\\s+"))
     if(f.size>=8) out.append("${f[0]}  destination=${routeIp(f[1])}  gateway=${routeIp(f[2])}  mask=${routeIp(f[7])}  flags=${f[3]}\n")
    }
    out.toString()
  }
  suspend fun discoverSubnet(context:Context):String=coroutineScope {
   val wm=context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
   val info=wm?.connectionInfo
   val ip=info?.ipAddress ?: 0
   if(ip==0) return@coroutineScope "Subnet discovery unavailable: no Wi-Fi IPv4 address."
   val b1=ip and 0xff; val b2=ip shr 8 and 0xff; val b3=ip shr 16 and 0xff
   val prefix24="$b1.$b2.$b3"
   val semaphore=Semaphore(32)
   val localHost=ip and 0xff
   val results=(1..254).filter { it != localHost }.map { host ->
    async(Dispatchers.IO) {
     ensureActive()
     for(port in listOf(80,443,22)) {
      val found=semaphore.withPermit {
       try {
        Socket().use { socket -> socket.tcpNoDelay=true; socket.connect(java.net.InetSocketAddress("$prefix24.$host",port),220); port }
       } catch (_:Exception) { null }
      }
      if(found!=null) {
       return@async "$prefix24.$host  OPEN $found${knownService(found)}"
      }
     }
     null
    }
   }.awaitAll().filterNotNull()
   val out=StringBuilder("Subnet discovery on $prefix24.0/24:\n")
   if(results.isEmpty()) out.append("No responsive hosts found on TCP 22, 80 or 443.") else results.forEach { out.append("$it\n") }
   out.toString()
  }
  suspend fun endpointDiscovery(raw:String):String=withContext(Dispatchers.IO) {
   var base=if(raw.startsWith("http://")||raw.startsWith("https://")) raw.trimEnd('/') else "https://$raw"
   val urlBase=try { URL(base).let { URL(it.protocol,it.host,it.port.takeIf { p -> p!=-1 } ?: -1,"/").toString().trimEnd('/') } } catch(_:Exception){ base }
   val paths=listOf("/robots.txt","/sitemap.xml","/.well-known/security.txt","/api","/swagger","/swagger/index.html","/openapi.json","/graphql","/admin","/login","/.git/HEAD")
   val out=StringBuilder("Endpoint discovery for $urlBase:\n")
   for(path in paths) {
    try {
     val c=URL(urlBase+path).openConnection() as HttpURLConnection
     c.connectTimeout=3500;c.readTimeout=3500;c.instanceFollowRedirects=true;c.requestMethod="GET"
     c.setRequestProperty("User-Agent","CyberAgent-Android/0.3")
     val status=c.responseCode
     val length=c.contentLength
     val location=c.headerFields.entries.firstOrNull { it.key?.equals("Location",true)==true }?.value?.joinToString()
     if(status !in 400..499 || path=="/robots.txt"||path=="/.well-known/security.txt") {
      out.append("$status  $path")
      if(length>=0) out.append("  bytes=$length")
      if(!location.isNullOrBlank()) out.append("  location=$location")
      out.append("\n")
     }
     c.disconnect()
    } catch(e:Exception) { out.append("ERR  $path  ${e.message}\n") }
   }
   out.toString()
  }
  private fun intIp(value:Int):String {
   if(value==0) return "(none)"
   return "${value and 0xff}.${value shr 8 and 0xff}.${value shr 16 and 0xff}.${value shr 24 and 0xff}"
  }
  private fun knownService(port:Int):String=ports.firstOrNull{it.first==port}?.let{ " (${it.second})" } ?: ""
  private fun routeIp(hex:String):String {
   return try {
    val value=hex.toLong(16)
    "${value and 0xff}.${value shr 8 and 0xff}.${value shr 16 and 0xff}.${value shr 24 and 0xff}"
   } catch (_:Exception) { hex }
  }
 private fun cleanHost(raw:String)=try { URL(if(raw.startsWith("http"))raw else "https://$raw").host.lowercase().removePrefix("www.") } catch(_:Exception) { raw.trim().removePrefix("http://").removePrefix("https://").substringBefore("/").substringBefore(":").lowercase().removePrefix("www.") }
}