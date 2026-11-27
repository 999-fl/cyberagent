package com.cyberagent.mobile

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.util.concurrent.TimeUnit

/** Small function-calling loop for network and analysis tools. */
object Agent {
 private val client=OkHttpClient.Builder().connectTimeout(20,TimeUnit.SECONDS).readTimeout(60,TimeUnit.SECONDS).build()
 private const val MAX_ROUNDS=4
 private fun toolsJson()=JSONArray().apply {
  put(tool("dns_lookup","Resolve DNS for a target hostname", "hostname"))
  put(tool("tcp_scan","Scan TCP ports using connect probes", "hostname"))
  put(tool("web_inspect","Fetch a web page's status, headers, redirect and TLS details", "url"))
  put(tool("endpoint_discovery","Probe common web metadata, API and management paths for a target", "url"))
  put(tool("validate_http","Validate common HTTP exposures and return confirmed versus inconclusive evidence", "url"))
  put(tool("active_php_validation","Run explicit active PHP and WordPress exposure checks that use non-destructive GET requests", "url"))
  put(tool("tls_inspect","Inspect a target's TLS handshake, peer certificate, validity and SANs on port 443", "hostname"))
 }
 private fun tool(name:String,desc:String,arg:String)=JSONObject().put("type","function").put("function",JSONObject().put("name",name).put("description",desc).put("parameters",JSONObject().put("type","object").put("properties",JSONObject().put(arg,JSONObject().put("type","string"))).put("required",JSONArray().put(arg)).put("additionalProperties",false)))
 suspend fun run(base:String,model:String,key:String,target:String,question:String,history:String,customInstructions:String="",directness:Int=75):String=withContext(Dispatchers.IO) {
  try {
    val messages=JSONArray().put(JSONObject().put("role","system").put("content","You are CyberAgent, an evidence-based mobile pentest assistant. Answer directly and can answer without a target. Never invent a finding or claim a check was performed unless it appears in the evidence. Clearly distinguish discovery from validation: an open port, HTTP 200, missing header, or discovered path is not automatically a vulnerability. Only call a finding confirmed when validation evidence contains matching content or an actual service response proving the issue. For each finding report: type, verdict, confidence, exact evidence, observed status/banner/content marker, potential impact, remediation, and recommended safe follow-up. Structure reports as: 1) Executive summary, 2) Confirmed findings, 3) Discovered but unconfirmed items, 4) Inconclusive checks, 5) Recommended follow-up. Directness preference: $directness/100. Custom user instructions:\n$customInstructions\nActivity context:\n$history")).put(JSONObject().put("role","user").put("content",question))
   var output=""
   repeat(MAX_ROUNDS) { round ->
    val payload=JSONObject().put("model",model).put("messages",messages).apply { if (scopeHost.isNotBlank()) { put("tools",toolsJson()); put("tool_choice","auto") } }
    val request=Request.Builder().url(normalizeEndpoint(base)).addHeader("Authorization","Bearer $key").addHeader("Content-Type","application/json").post(payload.toString().toRequestBody("application/json".toMediaType())).build()
    val response=client.newCall(request).execute().use { r -> if(!r.isSuccessful) return@withContext "API error ${r.code}: ${r.body?.string()?.take(1200)}" else JSONObject(r.body!!.string()) }
    val choices=response.optJSONArray("choices")
    val msg=choices?.optJSONObject(0)?.optJSONObject("message")
      ?: return@withContext "Provider response did not contain choices[0].message. Check the provider model, endpoint and response format."
    messages.put(msg)
    output=msg.optString("content","")
    val calls=msg.optJSONArray("tool_calls")
    val legacy=msg.optJSONObject("function_call")
    if((calls==null || calls.length()==0) && legacy==null) return@withContext output
    val normalizedCalls=JSONArray()
    if(calls!=null) for(i in 0 until calls.length()) normalizedCalls.put(calls.getJSONObject(i))
    if(legacy!=null) normalizedCalls.put(JSONObject().put("id","legacy-call-$round").put("function",legacy))
    for(i in 0 until normalizedCalls.length()) {
     val call=normalizedCalls.getJSONObject(i); val fn=call.optJSONObject("function") ?: continue; val name=fn.optString("name"); val args=try { JSONObject(fn.optString("arguments","{}")) } catch (_:Exception) { JSONObject() }; val argName = when(name) {
      "web_inspect", "endpoint_discovery", "validate_http", "active_php_validation" -> "url"
      else -> "hostname"
     }
     val requested=args.optString(argName,target).trim().ifBlank { target }
     val requestedHost=host(requested)
     val scopeHost=host(target)
     if(scopeHost.isNotBlank() && requestedHost.isNotBlank() && requestedHost != scopeHost) {
      messages.put(JSONObject().put("role","tool").put("tool_call_id",call.optString("id")).put("content","Blocked: requested target is outside the user-selected host scope ($scopeHost)."))
      continue
     }
     val result=when(name) {
      "dns_lookup" -> NetTools.dns(requested)
      "tcp_scan" -> NetTools.scan(requested)
      "web_inspect" -> NetTools.http(schemeUrl(target,requested),host(requested))
      "endpoint_discovery" -> NetTools.endpointDiscovery(requested)
      "validate_http" -> NetTools.validateHttp(requested)
      "active_php_validation" -> NetTools.activePhpValidation(requested)
      "tls_inspect" -> NetTools.tls(requested)
      else -> "Tool not registered."
     }
     val callId=call.optString("id")
     if(callId.startsWith("legacy-call-")) {
      messages.put(JSONObject().put("role","function").put("name",name).put("content",result))
     } else {
      messages.put(JSONObject().put("role","tool").put("tool_call_id",callId).put("content",result))
     }
    }
   }
   "Agent stopped after $MAX_ROUNDS tool rounds. Partial response:\n$output"
  } catch(e:Exception) { "Agent error: ${e.message ?: e.javaClass.simpleName}" }
 }
 suspend fun ask(base:String,model:String,key:String,question:String,history:String,customInstructions:String="",directness:Int=75):String=run(base,model,key,"",question,history,customInstructions,directness)
 suspend fun testProvider(base:String,model:String,key:String):String=withContext(Dispatchers.IO) {
  if(key.isBlank()) return@withContext "Provider test failed: API key is blank. Save a key in Settings."
  if(model.isBlank()) return@withContext "Provider test failed: model ID is blank."
  val endpoint=normalizeEndpoint(base)
  try {
   val payload=JSONObject().put("model",model).put("messages",JSONArray().put(JSONObject().put("role","user").put("content","Reply with OK only."))).put("max_tokens",8)
   val request=Request.Builder().url(endpoint).addHeader("Authorization","Bearer $key").addHeader("Content-Type","application/json").post(payload.toString().toRequestBody("application/json".toMediaType())).build()
   client.newCall(request).execute().use { r ->
    val body=r.body?.string().orEmpty()
    if(r.isSuccessful) {
     try {
      val parsed=JSONObject(body)
      val choices=parsed.optJSONArray("choices")
      val message=choices?.optJSONObject(0)?.optJSONObject("message")
      if(message==null) "Provider returned HTTP ${r.code}, but the response format was unexpected. Check whether this endpoint supports chat completions."
      else {
       val reply=message.optString("content","").trim()
       if(reply.isNotBlank()) "Provider test successful (HTTP ${r.code}). Model response: ${reply.take(120)}"
       else if(message.has("tool_calls")) "Provider test successful (HTTP ${r.code}). Response contains tool calls instead of text."
       else "Provider returned HTTP ${r.code}, but the model response was empty."
      }
     } catch(_:Exception) { "Provider returned HTTP ${r.code}, but its response was not valid JSON." }
    }
    else {
     val detail=try { JSONObject(body).optJSONObject("error")?.optString("message") ?: body } catch(_:Exception){body}
     when(r.code) {
      401 -> "HTTP 401: Authentication rejected or missing. Check API key and provider endpoint. Details: ${detail.take(500)}"
      403 -> "HTTP 403: Provider refused access (key permissions, credits, or account restriction). ${detail.take(500)}"
      404 -> "HTTP 404: Endpoint or model not found. Ensure the base URL ends in /v1 (not /chat/completions) and model ID is correct. ${detail.take(500)}"
      429 -> "HTTP 429: Rate limit or insufficient credits. ${detail.take(500)}"
      else -> "Provider test failed (HTTP ${r.code}): ${detail.take(700)}"
     }
    }
   }
  } catch(e:Exception) { "Provider test error: ${e.message ?: e.javaClass.simpleName}" }
 }
 private fun normalizeEndpoint(base:String):String {
  var value=base.trim().trimEnd('/')
  value=value.removeSuffix("/chat/completions").removeSuffix("/completions").trimEnd('/')
  if(value.isBlank()) return value
  return if(value.endsWith("/v1")) value+"/chat/completions" else value+"/v1/chat/completions"
 }
 private fun host(raw:String):String=try { URI(if(raw.contains("://"))raw else "https://$raw").host?.lowercase()?.removePrefix("www.") ?: raw.trim().lowercase().substringBefore("/") } catch(_:Exception){raw.trim().lowercase().substringBefore("/")}
 private fun schemeUrl(scope:String,request:String):String= if(request.contains("://"))request else if(scope.contains("://"))scope else "https://$request"
}
