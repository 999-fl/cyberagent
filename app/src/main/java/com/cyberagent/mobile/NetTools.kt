package com.cyberagent.mobile

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object NetTools {
 private val ports = listOf(21 to "FTP",22 to "SSH",23 to "Telnet",25 to "SMTP",53 to "DNS",80 to "HTTP",110 to "POP3",139 to "NetBIOS",143 to "IMAP",445 to "SMB",554 to "RTSP",631 to "IPP",443 to "HTTPS",8080 to "HTTP-alt",8443 to "HTTPS-alt",9000 to "Common-alt",3389 to "RDP")
 suspend fun scan(host:String):String = withContext(Dispatchers.IO) {
  val h=cleanHost(host)
  val results=ports.map { (port,service) -> async(Dispatchers.IO) { try { Socket().use { s -> s.connect(java.net.InetSocketAddress(h,port),650); "OPEN $port ($service)" } } catch (_:Exception){ null } } }.awaitAll().filterNotNull()
  val out=StringBuilder("TCP connect scan of $h (17 common ports; authorized targets only):\n")
  if(results.isEmpty()) out.append("No common TCP ports reachable (or scan blocked).") else results.forEach { out.append(it).append('\n') }
  out.toString()
 }
 suspend fun dns(host:String):String = withContext(Dispatchers.IO) {
  val h=cleanHost(host)
  try { InetAddress.getAllByName(h).joinToString("\n") { "$h → ${it.hostAddress}" } } catch(e:Exception) { "DNS error: ${e.message}" }
 }
 suspend fun http(raw:String):String = http(raw,cleanHost(raw))
 suspend fun http(raw:String,allowedHost:String):String = withContext(Dispatchers.IO) {
  try {
   var url=if(raw.startsWith("http://")||raw.startsWith("https://")) raw else "https://$raw"; val visited=mutableListOf<String>()
   val scope=cleanHost(allowedHost)
   for (hop in 0 until 5) {
    if(cleanHost(url)!=scope) return@withContext "Blocked redirect/request outside scope ($scope): $url"
    if(url in visited) return@withContext "Redirect loop detected:\n"+visited.joinToString(" → ")
    visited.add(url)
    val c=URL(url).openConnection() as HttpURLConnection; c.connectTimeout=7000;c.readTimeout=7000;c.instanceFollowRedirects=false;c.requestMethod="GET";c.setRequestProperty("User-Agent","CyberAgent-Android/0.2")
    val status=c.responseCode; val headerMap=c.headerFields.filterKeys{it!=null}; val headers=headerMap.entries.joinToString("\n"){ "${it.key}: ${it.value.joinToString()}" }
    val location=c.getHeaderField("Location"); val tls=if(c is HttpsURLConnection) "TLS cipher: ${c.cipherSuite}" else "Plain HTTP (no TLS)"
    val checks=StringBuilder("\nSecurity-header review:\n")
    val required=listOf("Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","Referrer-Policy")
    required.forEach { name -> if(headerMap.keys.any{it.equals(name,true)}) checks.append("PRESENT: $name\n") else checks.append("MISSING: $name\n") }
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
     val method=Regex("method=[\\\"']?([^\\\"'\\\\s>]+)",RegexOption.IGNORE_CASE).find(form)?.groupValues?.get(1)?.uppercase() ?: "GET (default)"
     if(method=="GET" && passwordFields>0) checks.append("Review: form(s) use GET/default method while password fields are present; verify form association and ensure credentials are not placed in URLs.\\n")
    }
    c.disconnect()
    if(status in 300..399 && !location.isNullOrBlank() && hop<4) {
      val next=URL(URL(url),location).toString()
      if(cleanHost(next)!=scope) return@withContext "Redirect blocked: destination outside defined scope ($scope).\nRedirect chain: ${visited.joinToString(" → ")} → $next"
      url=next; continue
    }
    return@withContext "URL: $url\nStatus: $status\n$tls\nRedirect chain: ${visited.joinToString(" → ")}\nHeaders:\n$headers\n$checks"
   }
   "Redirect limit reached: ${visited.joinToString(" → ")}"
  } catch(e:Exception) { "Web inspection failed: ${e.message}" }
 }
 private fun cleanHost(raw:String)=try { URL(if(raw.startsWith("http"))raw else "https://$raw").host.lowercase().removePrefix("www.") } catch(_:Exception) { raw.trim().removePrefix("http://").removePrefix("https://").substringBefore("/").substringBefore(":").lowercase().removePrefix("www.") }
}