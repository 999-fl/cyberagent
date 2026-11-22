package com.cyberagent.mobile

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object NetTools {
 private val ports = listOf(21,22,23,25,53,80,110,139,143,445,554,631,443,8080,8443,9000,3389)
 suspend fun scan(host:String):String = withContext(Dispatchers.IO) {
  val h=cleanHost(host); val out=StringBuilder("TCP connect scan of $h (common ports; authorized targets only):\n"); var found=false
  ports.forEach { p -> try { Socket().use { s -> s.connect(java.net.InetSocketAddress(h,p),450); out.append("OPEN $p\n"); found=true } } catch (_:Exception){} }
  if(!found) out.append("No common TCP ports reachable (or scan blocked).")
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
    val status=c.responseCode; val headerMap=c.headerFields.filterKeys{it!=null}; val headers=headerMap.entries.joinToString("\\n"){ "${it.key}: ${it.value.joinToString()}" }
    val location=c.getHeaderField("Location"); val tls=if(c is HttpsURLConnection) "TLS cipher: ${c.cipherSuite}" else "Plain HTTP (no TLS)"
    val checks=StringBuilder("\\nSecurity-header review:\\n")
    val required=listOf("Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options","X-Frame-Options","Referrer-Policy")
    required.forEach { name -> if(headerMap.keys.any{it.equals(name,true)}) checks.append("PRESENT: $name\\n") else checks.append("MISSING: $name\\n") }
    val cookies=headerMap.entries.filter{it.key.equals("Set-Cookie",true)}.flatMap{it.value}
    cookies.forEach { cookie -> checks.append("Cookie flags: ${cookie.substringAfter(";").trim()}\\n") }
    val body=try { val stream=if(status>=400)c.errorStream else c.inputStream; stream?.bufferedReader()?.use{it.readText().take(200000)} ?: "" } catch(_:Exception){""}
    val forms=Regex("<form\\b[^>]*>",RegexOption.IGNORE_CASE).findAll(body).map{it.value}.toList()
    checks.append("Forms found: ${forms.size}\\n")
    forms.take(10).forEachIndexed { i,form -> checks.append("Form ${i+1}: ${form.replace(Regex("\\s+")," ").take(400)}\\n") }
    val inputs=Regex("<input\\b[^>]*>",RegexOption.IGNORE_CASE).findAll(body).map{it.value}.toList()
    checks.append("Input fields found: ${inputs.size}\\n")
    inputs.take(25).forEach { tag -> val type=Regex("type=[\\\"']?([^\\\"'\\s>]+)",RegexOption.IGNORE_CASE).find(tag)?.groupValues?.get(1) ?: "text"; val name=Regex("name=[\\\"']?([^\\\"'\\s>]+)",RegexOption.IGNORE_CASE).find(tag)?.groupValues?.get(1) ?: "(unnamed)"; checks.append("Input: type=$type name=$name\\n") }
    c.disconnect()
    if(status in 300..399 && !location.isNullOrBlank() && hop<4) {
      val next=URL(URL(url),location).toString()
      if(cleanHost(next)!=scope) return@withContext "Redirect blocked: destination outside defined scope ($scope).\nRedirect chain: ${visited.joinToString(" → ")} → $next"
      url=next; continue
    }
    return@withContext "URL: $url\nStatus: $status\n$tls\nRedirect chain: ${visited.joinToString(" → ")}\nHeaders:\n$headers"
   }
   "Redirect limit reached: ${visited.joinToString(" → ")}"
  } catch(e:Exception) { "Web inspection failed: ${e.message}" }
 }
 private fun cleanHost(raw:String)=try { URL(if(raw.startsWith("http"))raw else "https://$raw").host.lowercase().removePrefix("www.") } catch(_:Exception) { raw.trim().removePrefix("http://").removePrefix("https://").substringBefore("/").substringBefore(":").lowercase().removePrefix("www.") }
}