package com.cyberagent.mobile

import android.content.Intent\nimport android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Security
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CyberAgentApp() {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    var apiKey by remember { mutableStateOf(KeyVault.load(context)) }
    val prefs = context.getSharedPreferences("cyberagent_config", Context.MODE_PRIVATE)\n    var endpoint by remember { mutableStateOf(prefs.getString("endpoint", "https://openrouter.ai/api/v1") ?: "") }
    var model by remember { mutableStateOf(prefs.getString("model", "deepseek/deepseek-chat") ?: "") }
    var settingsOpen by remember { mutableStateOf(false) }
    var target by remember { mutableStateOf("") }
    var prompt by remember { mutableStateOf("") }
    var log by remember { mutableStateOf("Ready. Configure your provider in Settings to enable AI analysis.") }
    var busy by remember { mutableStateOf(false) }
    fun append(message: String) { log = (log + "\n\n" + message).takeLast(24000) }

    MaterialTheme(colorScheme = darkColorScheme(
        primary = androidx.compose.ui.graphics.Color(0xFF76E5B1),
        secondary = androidx.compose.ui.graphics.Color(0xFF8DB7FF),
        surface = androidx.compose.ui.graphics.Color(0xFF151A20),
        background = androidx.compose.ui.graphics.Color(0xFF0B1015)
    )) {
        Scaffold(topBar = {
            TopAppBar(
                title = { Column { Text("CYBERAGENT", style = MaterialTheme.typography.titleLarge); Text("SECURITY WORKSPACE", style = MaterialTheme.typography.labelSmall) } },
                actions = { IconButton(onClick = { settingsOpen = true }) { Icon(Icons.Default.Settings, "Settings") } },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface)
            )
        }) { pad ->
            Column(Modifier.padding(pad).fillMaxSize()) {
                androidx.compose.foundation.lazy.LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                    modifier = Modifier.fillMaxSize()
                ) {
                    item {
                        Card(shape = RoundedCornerShape(24.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                            Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Icon(Icons.Default.Info, null, tint = MaterialTheme.colorScheme.primary)
                                Text("Assessment workspace", style = MaterialTheme.typography.headlineSmall)
                                Text("Lightweight reconnaissance and evidence collection for systems you are authorised to assess.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    AssistChip(onClick = { settingsOpen = true }, label = { Text(if (apiKey.isBlank()) "Provider not configured" else "API key saved") })
                                    AssistChip(onClick = {}, label = { Text(if (busy) "Working" else "Ready") })
                                }
                            }
                        }
                    }
                    item {
                        Text("TARGET", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                        OutlinedTextField(target, { target = it }, placeholder = { Text("Hostname or URL") }, singleLine = true, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp))
                    }
                    item {
                        Text("QUICK RECON", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                            ToolCard("DNS", "Lookup", Icons.Default.Info, Modifier.weight(1f), !busy && target.isNotBlank()) {
                                busy = true; scope.launch { try { append(NetTools.dns(target)) } catch (e: Exception) { append("DNS error: ${e.message}") } finally { busy = false } }
                            }
                            ToolCard("TCP", "Scan", Icons.Default.Info, Modifier.weight(1f), !busy && target.isNotBlank()) {
                                busy = true; scope.launch { try { append(NetTools.scan(target)) } catch (e: Exception) { append("Scan error: ${e.message}") } finally { busy = false } }
                            }
                            ToolCard("HTTP", "Inspect", Icons.Default.Search, Modifier.weight(1f), !busy && target.isNotBlank()) {
                                busy = true; scope.launch { try { append(NetTools.http(target)) } catch (e: Exception) { append("HTTP error: ${e.message}") } finally { busy = false } }
                            }
                        }
                    }
                    item {
                        Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text("AI ANALYSIS", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                                OutlinedTextField(prompt, { prompt = it }, label = { Text("Analysis objective") }, modifier = Modifier.fillMaxWidth(), minLines = 2, shape = RoundedCornerShape(14.dp))
                                Button(onClick = {
                                    busy = true
                                    scope.launch { try { append(Agent.run(endpoint, model, apiKey, target, prompt, log)) } catch (e: Exception) { append("Agent error: ${e.message}") } finally { busy = false } }
                                }, enabled = !busy && prompt.isNotBlank() && apiKey.isNotBlank() && target.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text(if (busy) "Working…" else "Run analysis") }
                                if (apiKey.isBlank()) Text("Set an API key in Settings to enable AI.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                    item {
                        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) { Text("EVIDENCE", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary); Text("Run history", style = MaterialTheme.typography.titleMedium) }
                            TextButton(onClick = { try { val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager; cm.setPrimaryClip(android.content.ClipData.newPlainText("CyberAgent log", log)); append("Log copied to clipboard.") } catch (_: Exception) { append("Clipboard copy failed.") } }) { Icon(Icons.Default.Info, null); Text("Copy") }\n                            TextButton(enabled = !busy, onClick = { log = "Log cleared." }) { Text("Clear") }
                            TextButton(onClick = {
                                val send = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_SUBJECT, "CyberAgent evidence"); putExtra(Intent.EXTRA_TEXT, "CyberAgent evidence log\nTarget: $target\n\n$log") }
                                context.startActivity(Intent.createChooser(send, "Export evidence"))
                            }) { Text("Export") }
                        }
                    }
                    item { Card(shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) { Text(log, Modifier.padding(14.dp), style = MaterialTheme.typography.bodySmall) } }
                    item { Text("CyberAgent • lightweight assessment tools", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
            }
        }
        if (settingsOpen) {
            AlertDialog(
                onDismissRequest = { settingsOpen = false },
                title = { Text("Settings") },
                text = { Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("API PROVIDER", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                    OutlinedTextField(endpoint, { endpoint = it }, label = { Text("API base URL") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                    OutlinedTextField(model, { model = it }, label = { Text("Model ID") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                    OutlinedTextField(apiKey, { apiKey = it }, label = { Text("API key") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
                    Text("API key encrypted using Android Keystore. Provider and model preferences are saved locally.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } },
                confirmButton = { TextButton(onClick = { try { KeyVault.save(context, apiKey); prefs.edit().putString("endpoint", endpoint.trim()).putString("model", model.trim()).apply(); append("Provider settings saved."); settingsOpen = false } catch (e: Exception) { append("Key save failed: ${e.message}") } }) { Text("Save") } },
                dismissButton = { TextButton(onClick = { apiKey = ""; KeyVault.clear(context); append("Stored API key cleared."); settingsOpen = false }) { Text("Forget key") } }
            )
        }
    }
}

@Composable
private fun ToolCard(title: String, subtitle: String, icon: androidx.compose.ui.graphics.vector.ImageVector, modifier: Modifier, enabled: Boolean, action: () -> Unit) {
    Card(modifier, shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Icon(icon, null, tint = MaterialTheme.colorScheme.primary)
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Button(onClick = action, enabled = enabled, modifier = Modifier.fillMaxWidth(), contentPadding = PaddingValues(horizontal = 4.dp)) { Text("Run") }
        }
    }
}
