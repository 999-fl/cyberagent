package com.cyberagent.mobile

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardType
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
 var apiKey by remember { mutableStateOf("") }
 var endpoint by remember { mutableStateOf("https://openrouter.ai/api/v1") }
 var model by remember { mutableStateOf("deepseek/deepseek-chat") }
 var target by remember { mutableStateOf("") }
 var prompt by remember { mutableStateOf("") }
 var log by remember { mutableStateOf("CyberAgent alpha. Configure provider, then use the network tools on networks you own or are authorized to assess.") }
 var busy by remember { mutableStateOf(false) }
 MaterialTheme(colorScheme = darkColorScheme()) {
  Scaffold { pad ->
   Column(Modifier.padding(pad).padding(16.dp).fillMaxSize(), verticalArrangement=Arrangement.spacedBy(8.dp)) {
    Text("CYBERAGENT", style=MaterialTheme.typography.headlineSmall)
    Text("Android security assistant • no ads • no root", style=MaterialTheme.typography.bodySmall)
    OutlinedTextField(endpoint, { endpoint=it }, label={Text("API base URL")}, modifier=Modifier.fillMaxWidth())
    OutlinedTextField(model, {model=it}, label={Text("Model ID")}, modifier=Modifier.fillMaxWidth())
    OutlinedTextField(apiKey, {apiKey=it}, label={Text("API key")}, visualTransformation=PasswordVisualTransformation(), modifier=Modifier.fillMaxWidth())
    OutlinedTextField(target, {target=it}, label={Text("Target (host / URL)")}, modifier=Modifier.fillMaxWidth())
    Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
     Button(enabled=!busy && target.isNotBlank(), onClick={busy=true; scope.launch { log += "\n\n"+NetTools.scan(target)+"\n"; busy=false }}) { Text("TCP scan") }
     Button(enabled=!busy && target.isNotBlank(), onClick={busy=true; scope.launch { log += "\n\n"+NetTools.http(target)+"\n"; busy=false }}) { Text("HTTP inspect") }
     Button(enabled=!busy && target.isNotBlank(), onClick={busy=true; scope.launch { log += "\n\n"+NetTools.dns(target)+"\n"; busy=false }}) { Text("DNS lookup") }
    }
    OutlinedTextField(prompt, {prompt=it}, label={Text("Ask agent / analyse results")}, modifier=Modifier.fillMaxWidth(), minLines=2)
    Button(enabled=!busy && prompt.isNotBlank() && apiKey.isNotBlank(), onClick={busy=true; scope.launch { log += "\n\n"+Agent.run(endpoint,model,apiKey,target,prompt,log)+"\n"; busy=false }}) { Text(if(busy) "Working…" else "Run agent") }
    Text("Activity / evidence", style=MaterialTheme.typography.titleMedium)
    Box(Modifier.fillMaxSize()) { LazyColumn { item { Text(log) } } }
   }
  }
 }
}
