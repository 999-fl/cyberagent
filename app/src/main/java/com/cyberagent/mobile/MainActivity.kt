package com.cyberagent.mobile

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
 override fun onCreate(savedInstanceState: Bundle?) {
  super.onCreate(savedInstanceState)
  setContent { CyberAgentApp() }
 }
}

@Composable
fun CyberAgentApp() {
 val scope = rememberCoroutineScope()
 val context = LocalContext.current
 var apiKey by remember { mutableStateOf(KeyVault.load(context)) }
 var endpoint by remember { mutableStateOf("https://openrouter.ai/api/v1") }
 var model by remember { mutableStateOf("deepseek/deepseek-chat") }
 var target by remember { mutableStateOf("") }
 var prompt by remember { mutableStateOf("") }
 var log by remember { mutableStateOf("CyberAgent alpha. Configure provider, then use network tools on networks you own or are authorized to assess.") }
 var busy by remember { mutableStateOf(false) }
 fun append(message:String) { log=(log+"\n\n"+message).takeLast(24000) }
 MaterialTheme(colorScheme = darkColorScheme()) {
  Scaffold { pad ->
   Column(Modifier.padding(pad).padding(16.dp).fillMaxSize(), verticalArrangement=Arrangement.spacedBy(8.dp)) {
    Text("CYBERAGENT", style=MaterialTheme.typography.headlineSmall)
    Text("Android security assistant • no ads • no root", style=MaterialTheme.typography.bodySmall)
    OutlinedTextField(endpoint, { endpoint=it }, label={Text("API base URL")}, modifier=Modifier.fillMaxWidth())
    OutlinedTextField(model, {model=it}, label={Text("Model ID")}, modifier=Modifier.fillMaxWidth())
    OutlinedTextField(apiKey, {apiKey=it}, label={Text("API key (encrypted on device)")}, visualTransformation=PasswordVisualTransformation(), modifier=Modifier.fillMaxWidth())\n    Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {\n     Button(onClick={ try { KeyVault.save(context,apiKey); append("API key saved encrypted with Android Keystore.") } catch(e:Exception) { append("Key save failed: ${e.message}") } }) { Text("Save key") }\n     TextButton(onClick={apiKey="";KeyVault.clear(context);append("Stored API key cleared.")}) { Text("Forget key") }\n    }
    OutlinedTextField(target, {target=it}, label={Text("Target (host / URL)")}, modifier=Modifier.fillMaxWidth())
    Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
     Button(enabled=!busy && target.isNotBlank(), onClick={busy=true; scope.launch { try { append(NetTools.scan(target)) } catch(e:Exception) { append("Scan error: ${e.message}") } finally { busy=false } }}) { Text("TCP scan") }
     Button(enabled=!busy && target.isNotBlank(), onClick={busy=true; scope.launch { try { append(NetTools.http(target)) } catch(e:Exception) { append("HTTP inspect error: ${e.message}") } finally { busy=false } }}) { Text("HTTP inspect") }
     Button(enabled=!busy && target.isNotBlank(), onClick={busy=true; scope.launch { try { append(NetTools.dns(target)) } catch(e:Exception) { append("DNS error: ${e.message}") } finally { busy=false } }}) { Text("DNS lookup") }
    }
    OutlinedTextField(prompt, {prompt=it}, label={Text("Ask agent / analyse results")}, modifier=Modifier.fillMaxWidth(), minLines=2)
    Button(enabled=!busy && prompt.isNotBlank() && apiKey.isNotBlank() && target.isNotBlank(), onClick={busy=true; scope.launch { try { append(Agent.run(endpoint,model,apiKey,target,prompt,log)) } catch(e:Exception) { append("Agent error: ${e.message}") } finally { busy=false } }}) { Text(if(busy) "Working…" else "Run agent") }
    Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
     Text("Activity / evidence", style=MaterialTheme.typography.titleMedium)
     TextButton(onClick={log="Log cleared."},enabled=!busy) {Text("Clear")}
     TextButton(onClick={
      val send=Intent(Intent.ACTION_SEND).apply { type="text/plain"; putExtra(Intent.EXTRA_SUBJECT,"CyberAgent evidence"); putExtra(Intent.EXTRA_TEXT,"CyberAgent evidence log\nTarget: $target\n\n$log") }
      context.startActivity(Intent.createChooser(send,"Export evidence"))
     }) {Text("Export")}
    }
    Box(Modifier.fillMaxSize()) { LazyColumn { item { Text(log) } } }
   }
  }
 }
}
