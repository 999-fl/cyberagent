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

/** Small, bounded function-calling loop. Tools are restricted to the declared target. */
object Agent {
 private val client=OkHttpClient.Builder().connectTimeout(20,TimeUnit.SECONDS).readTimeout(60,TimeUnit.SECONDS).build()
 private const val MAX_ROUNDS=4
 private fun toolsJson()=JSONArray().apply {
  put(tool("dns_lookup","Resolve DNS for the scoped target hostname", "hostname"))
  put(tool("tcp_scan","Check a small common-port set using TCP connect for the scoped target", "hostname"))
  put(tool("web_inspect","Fetch a web page's status, headers, redirect and TLS details for the scoped target URL", "url"))
 }
 private fun tool(name:String,desc:String,arg:String)=JSONObject().put("type","function").put("function",JSONObject().put("name",name).put("description",desc).put("parameters",JSONObject().put("type","object").put("properties",JSONObject().put(arg,JSONObject().put("type","string"))).put("required",JSONArray().put(arg)).put("additionalProperties",false)))
 suspend fun run(base:String,model:String,key:String,target:String,question:String,history:String):String=withContext(Dispatchers.IO) {
  try {
   val scopeHost=host(target); if(scopeHost.isBlank()) return@withContext "Enter a target hostname or URL to define the tool scope."
   val messages=JSONArray().put(JSONObject().put("role","system").put("content","You are CyberAgent, an evidence-based mobile security agent. Scope is strictly limited to hostname: $scopeHost. Only use the provided tools, which perform passive DNS/web GET and modest TCP connect checks. Do not attempt exploitation, credential submission, brute force, injection payloads, destructive changes or scope expansion. Explain findings and propose safe remediation. Use tools when useful and do not claim checks not performed. Activity context:\n$history")).put(JSONObject().put("role","user").put("content",question))
   var output=""
   repeat(MAX_ROUNDS) { round ->
    val payload=JSONObject().put("model",model).put("messages",messages).put("tools",toolsJson()).put("tool_choice","auto")
    val request=Request.Builder().url(normalizeEndpoint(base)).addHeader("Authorization","Bearer $key").addHeader("Content-Type","application/json").post(payload.toString().toRequestBody("application/json".toMediaType())).build()
    val response=client.newCall(request).execute().use { r -> if(!r.isSuccessful) return@withContext "API error ${r.code}: ${r.body?.string()?.take(1200)}" else JSONObject(r.body!!.string()) }
    val msg=response.getJSONArray("choices").getJSONObject(0).getJSONObject("message"); messages.put(msg)
    output=msg.optString("content","")
    val calls=msg.optJSONArray("tool_calls")
    if(calls==null || calls.length()==0) return@withContext output
    for(i in 0 until calls.length()) {
     val call=calls.getJSONObject(i); val fn=call.getJSONObject("function"); val name=fn.getString("name"); val args=JSONObject(fn.getString("arguments")); val requested=args.optString(if(name=="web_inspect")"url" else "hostname",scopeHost)
     val result=if(host(requested)!=scopeHost) "Blocked: tool argument is outside the defined target scope ($scopeHost)." else when(name) {
      "dns_lookup" -> NetTools.dns(scopeHost)
      "tcp_scan" -> NetTools.scan(scopeHost)
      "web_inspect" -> NetTools.http(schemeUrl(target,requested),scopeHost)
      else -> "Tool not registered."
     }
     messages.put(JSONObject().put("role","tool").put("tool_call_id",call.optString("id")).put("content",result))
    }
   }
   "Agent stopped after $MAX_ROUNDS tool rounds. Partial response:\n$output"
  } catch(e:Exception) { "Agent error: ${e.message ?: e.javaClass.simpleName}" }
 }
 suspend fun ask(base:String,model:String,key:String,question:String,history:String):String=run(base,model,key,"",question,history)
 suspend fun testProvider(base:String,model:String,key:String):String=withContext(Dispatchers.IO) {
  if(key.isBlank()) return@withContext "Provider test failed: API key is blank. Save a key in Settings."
  if(model.isBlank()) return@withContext "Provider test failed: model ID is blank."
  val endpoint=normalizeEndpoint(base)
  try {
   val payload=JSONObject().put("model",model).put("messages",JSONArray().put(JSONObject().put("role","user").put("content","Reply with OK only."))).put("max_tokens",8)
   val request=Request.Builder().url(endpoint).addHeader("Authorization","Bearer $key").addHeader("Content-Type","application/json").post(payload.toString().toRequestBody("application/json".toMediaType())).build()
   client.newCall(request).execute().use { r ->
    val body=r.body?.string().orEmpty()
    if(r.isSuccessful) "Provider test successful (HTTP ${r.code}). Model responded."
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
