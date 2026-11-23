package com.cyberagent.mobile

import android.content.Intent
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
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
    val prefs = context.getSharedPreferences("cyberagent_config", Context.MODE_PRIVATE)
    var endpoint by remember { mutableStateOf(prefs.getString("endpoint", "https://openrouter.ai/api/v1") ?: "") }
    var model by remember { mutableStateOf(prefs.getString("model", "deepseek/deepseek-chat") ?: "") }
    var settingsOpen by remember { mutableStateOf(false) }
    var customInstructions by remember { mutableStateOf(prefs.getString("custom_instructions", "") ?: "") }
    var directness by remember { mutableIntStateOf(prefs.getInt("directness", 75).coerceIn(0, 100)) }
    var providerTestResult by remember { mutableStateOf("") }
    var target by remember { mutableStateOf("") }
    var prompt by remember { mutableStateOf("") }
    var log by remember { mutableStateOf("Target evidence will appear here. Configure your provider in Settings to enable AI analysis.") }
    var aiOutput by remember { mutableStateOf("AI findings will appear in this dedicated panel.") }
    var busy by remember { mutableStateOf(false) }
    fun append(message: String) { val stamp = java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")); log = (log + "\n\n[" + stamp + "] " + message).takeLast(24000) }
    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) { busy = true; scope.launch { try { append(ApkInspector.inspect(context, uri)) } finally { busy = false } } } }
    val locationPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        busy = true
        scope.launch {
            try { append(NetTools.wifi(context)) }
            catch (e: Exception) { append("Wi-Fi inventory failed: ${e.message}") }
            finally { busy = false }
        }
    }

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
                        Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { Text("APK REVIEW", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary); Text("Inspect an Android APK permission inventory and metadata locally.", color = MaterialTheme.colorScheme.onSurfaceVariant); Button(onClick = { apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Select APK to inspect") } } }
                    }
                    item {
                        Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("WI-FI INVENTORY", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                                Text("Review the active network, local gateway/DNS configuration and nearby Wi-Fi metadata.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Button(onClick = {
                                    val fineGranted=ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_FINE_LOCATION)==android.content.pm.PackageManager.PERMISSION_GRANTED
                                    val coarseGranted=ContextCompat.checkSelfPermission(context, android.Manifest.permission.ACCESS_COARSE_LOCATION)==android.content.pm.PackageManager.PERMISSION_GRANTED
                                    if(fineGranted || coarseGranted) {
                                        busy=true
                                        scope.launch { try { append(NetTools.wifi(context)) } catch(e:Exception){ append("Wi-Fi inventory failed: ${e.message}") } finally { busy=false } }
                                    } else {
                                        locationPermissionLauncher.launch(arrayOf(android.Manifest.permission.ACCESS_FINE_LOCATION,android.Manifest.permission.ACCESS_COARSE_LOCATION))
                                    }
                                }, enabled=!busy, modifier=Modifier.fillMaxWidth()) { Text("Inspect local Wi-Fi") }
                            }
                        }
                    }
                    item {
                        Text("QUICK RECON", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                            ToolCard("DNS", "Lookup", Icons.Default.Info, Modifier.weight(1f), !busy && target.isNotBlank()) {
                                busy = true; scope.launch { try { append(NetTools.dns(target)) } catch (e: Exception) { append("DNS error: ${e.message}") } finally { busy = false } }
                            }
                            ToolCard("TCP", "Scan", Icons.Default.Info, Modifier.weight(1f), !busy && target.isNotBlank()) {
                                busy = true; scope.launch { try { append(NetTools.scan(target)) } catch (e: Exception) { append("Scan error: ${e.message}") } finally { busy = false } }
                            }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                            ToolCard("HTTP", "Inspect", Icons.Default.Search, Modifier.weight(1f), !busy && target.isNotBlank()) {
                                busy = true; scope.launch { try { append(NetTools.http(target)) } catch (e: Exception) { append("HTTP error: ${e.message}") } finally { busy = false } }
                            }
                            ToolCard("TLS", "Certificate", Icons.Default.Info, Modifier.weight(1f), !busy && target.isNotBlank()) {
                                busy = true; scope.launch { try { append(NetTools.tls(target)) } catch (e: Exception) { append("TLS error: ${e.message}") } finally { busy = false } }
                            }
                        }
                        }
                    }
                    item {
                        Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text("NETWORK DISCOVERY", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                                Text("Inspect local kernel routing, neighbor entries and responsive hosts on the active Wi-Fi subnet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                                    Button(onClick = {
                                        busy=true
                                        scope.launch { try { append(NetTools.arpAndRoutes()) } catch(e:Exception){ append("Route inspection failed: ${e.message}") } finally { busy=false } }
                                    }, enabled=!busy, modifier=Modifier.weight(1f)) { Text("ARP + routes") }
                                    Button(onClick = {
                                        busy=true
                                        scope.launch { try { append(NetTools.discoverSubnet(context)) } catch(e:Exception){ append("Subnet discovery failed: ${e.message}") } finally { busy=false } }
                                    }, enabled=!busy, modifier=Modifier.weight(1f)) { Text("Discover hosts") }
                                }
                            }
                        }
                    }
                    item {
                        Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("WEB ENDPOINTS", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                                Text("Check robots, sitemap, security metadata, API and common management paths.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Button(onClick = {
                                    busy=true
                                    scope.launch { try { append(NetTools.endpointDiscovery(target)) } catch(e:Exception){ append("Endpoint discovery failed: ${e.message}") } finally { busy=false } }
                                }, enabled=!busy&&target.isNotBlank(), modifier=Modifier.fillMaxWidth()) { Text("Discover web endpoints") }
                            }
                        }
                    }
                    item {
                        Button(onClick = {
                            busy = true
                            scope.launch {
                                append("=== Combined reconnaissance started ===")
                                try { append(NetTools.dns(target)) } catch (e: Exception) { append("DNS stage failed: ${e.message}") }
                                try { append(NetTools.scan(target)) } catch (e: Exception) { append("TCP stage failed: ${e.message}") }
                                try { append(NetTools.http(target)) } catch (e: Exception) { append("HTTP stage failed: ${e.message}") }
                                try { append(NetTools.tls(target)) } catch (e: Exception) { append("TLS stage failed: ${e.message}") }
                                try { append(NetTools.endpointDiscovery(target)) } catch (e: Exception) { append("Endpoint discovery stage failed: ${e.message}") }
                                append("=== Combined reconnaissance completed (stage errors recorded) ===")
                                busy = false
                            }
                        }, enabled = !busy && target.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Run all reconnaissance") }
                    }
                    item {
                        Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text("AI ANALYSIS", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                                OutlinedTextField(prompt, { prompt = it }, label = { Text("Pentest question or analysis objective") }, placeholder = { Text("Summarise verified risks and recommend next checks") }, modifier = Modifier.fillMaxWidth(), minLines = 2, shape = RoundedCornerShape(14.dp))
                                Button(onClick = {
                                    busy = true
                                    val objective=prompt.ifBlank { "Analyse all collected evidence for HTTP, TLS, DNS, TCP and Wi-Fi findings. Produce a concise pentest summary, rank verified risks, explain impact and confidence, provide concrete remediation, and list practical follow-up checks." }
                                    scope.launch { try { aiOutput = Agent.run(endpoint, model, apiKey, target, objective, log, customInstructions, directness) } catch (e: Exception) { aiOutput = "Agent error: ${e.message}" } finally { busy = false } }
                                }, enabled = !busy && apiKey.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text(if (busy) "Analysing evidence…" else "Generate pentest summary") }
                                if (apiKey.isBlank()) Text("Set an API key in Settings to enable AI.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Text("AI RESULTS", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.background), shape = RoundedCornerShape(16.dp)) { Column(Modifier.padding(14.dp)) { Text(aiOutput, style = MaterialTheme.typography.bodyLarge, lineHeight = MaterialTheme.typography.bodyLarge.lineHeight) } }
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { TextButton(onClick = { try { val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager; cm.setPrimaryClip(android.content.ClipData.newPlainText("CyberAgent AI analysis", aiOutput)) } catch (_: Exception) {} }) { Text("Copy AI") }; TextButton(onClick = { aiOutput = "AI findings will appear in this dedicated panel." }) { Text("Clear AI") } }
                            }
                        }
                    }
                    item {
                        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) { Text("EVIDENCE", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary); Text("Run history", style = MaterialTheme.typography.titleMedium) }
                            TextButton(onClick = { try { val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager; cm.setPrimaryClip(android.content.ClipData.newPlainText("CyberAgent log", log)); append("Log copied to clipboard.") } catch (_: Exception) { append("Clipboard copy failed.") } }) { Icon(Icons.Default.Info, null); Text("Copy") }
                            TextButton(enabled = !busy, onClick = { log = "Log cleared." }) { Text("Clear") }
                            TextButton(onClick = {
                                val send = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_SUBJECT, "CyberAgent evidence"); putExtra(Intent.EXTRA_TEXT, "CyberAgent evidence log\nTarget: $target\n\n$log\n\nAI ANALYSIS\n$aiOutput") }
                                context.startActivity(Intent.createChooser(send, "Export evidence"))
                            }) { Text("Export") }
                        }
                    }
                    item { Card(shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) { Column(Modifier.padding(14.dp).heightIn(max = 300.dp).verticalScroll(rememberScrollState())) { Text(log, style = MaterialTheme.typography.bodySmall, lineHeight = MaterialTheme.typography.bodySmall.lineHeight) } } }
                    item { Text("CyberAgent • lightweight assessment tools", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
            }
        }
        if (settingsOpen) {
            AlertDialog(
                onDismissRequest = { settingsOpen = false },
                title = { Text("AI Settings") },
                text = { Column(Modifier.heightIn(max = 560.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("PROVIDER", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                    OutlinedTextField(endpoint, { endpoint = it }, label = { Text("API base URL") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                    OutlinedTextField(model, { model = it }, label = { Text("Model ID") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                    OutlinedTextField(apiKey, { apiKey = it }, label = { Text("API key") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
                    Button(
                        onClick = {
                            busy = true
                            providerTestResult = "Testing…"
                            scope.launch {
                                try {
                                    providerTestResult = Agent.testProvider(endpoint, model, apiKey)
                                    append(providerTestResult)
                                } catch (e: Exception) {
                                    providerTestResult = "Provider test failed: ${e.message}"
                                    append(providerTestResult)
                                } finally {
                                    busy = false
                                }
                            }
                        },
                        enabled = !busy && apiKey.isNotBlank() && endpoint.isNotBlank() && model.isNotBlank(),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(if (busy) "Testing provider…" else "Test provider connection")
                    }
                    if (providerTestResult.isNotBlank()) Text(providerTestResult, style = MaterialTheme.typography.bodySmall)
                    Divider()
                    Text("AI BEHAVIOUR", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                    Text("Directness / caveats: $directness%", style = MaterialTheme.typography.bodyMedium)
                    Slider(value = directness.toFloat(), onValueChange = { directness = it.toInt() }, valueRange = 0f..100f, steps = 9)
                    Text("Higher settings favour direct, practical answers with fewer unnecessary caveats.", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(customInstructions, { customInstructions = it }, label = { Text("Custom AI instructions") }, placeholder = { Text("Personality, formatting, expertise, preferred workflow…") }, modifier = Modifier.fillMaxWidth(), minLines = 5)
                    Text("Custom instructions affect future analyses.", style = MaterialTheme.typography.bodySmall)
                } },
                confirmButton = { TextButton(onClick = { try { KeyVault.save(context, apiKey); prefs.edit().putString("endpoint", endpoint.trim()).putString("model", model.trim()).putString("custom_instructions", customInstructions).putInt("directness", directness).apply(); append("AI settings saved."); settingsOpen = false } catch (e: Exception) { append("Settings save failed: ${e.message}") } }) { Text("Save") } },
                dismissButton = { TextButton(onClick = { apiKey = ""; KeyVault.clear(context); append("Stored API key cleared.") }) { Text("Forget key") } }
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
