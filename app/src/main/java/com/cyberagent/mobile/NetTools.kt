package com.cyberagent.mobile

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object NetTools {
 private val ports = listOf(21,22,23,25,53,80,110,139,143,443,445,554,631,8080,8443,9000,3389)
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
 suspend fun http(raw:String):String = withContext(Dispatchers.IO) {
  try {
   var url=if(raw.startsWith("http://")||raw.startsWith("https://")) raw else "https://$raw"; val visited=mutableListOf<String>()
   for (hop in 0 until 5) {
    if(url in visited) return@withContext "Redirect loop detected:\n"+visited.joinToString(" → ")
    visited.add(url)
    val c=URL(url).openConnection() as HttpURLConnection; c.connectTimeout=7000;c.readTimeout=7000;c.instanceFollowRedirects=false;c.requestMethod="GET";c.setRequestProperty("User-Agent","CyberAgent-Android/0.1")
    val status=c.responseCode; val headers=c.headerFields.filterKeys{it!=null}.entries.joinToString("\n"){ "${it.key}: ${it.value.joinToString()}" }
    val location=c.getHeaderField("Location"); val tls=if(c is HttpsURLConnection) "TLS cipher: ${c.cipherSuite}" else "Plain HTTP (no TLS)"; c.disconnect()
    if(status in 300..399 && !location.isNullOrBlank() && hop<4) { url=URL(URL(url),location).toString(); continue }
    return@withContext "URL: $url\nStatus: $status\n$tls\nRedirect chain: ${visited.joinToString(" → ")}\nHeaders:\n$headers"
   }
   "Redirect limit reached: ${visited.joinToString(" → ")}"
  } catch(e:Exception) { "Web inspection failed: ${e.message}" }
 }
 private fun cleanHost(raw:String)=raw.trim().removePrefix("http://").removePrefix("https://").substringBefore("/").substringBefore(":")
}
