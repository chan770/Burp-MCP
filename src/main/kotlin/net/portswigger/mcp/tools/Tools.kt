package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.ReportFormat
import burp.api.montoya.scanner.ScanTask
import burp.api.montoya.utilities.CompressionType
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.utilities.DigestAlgorithm
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.ActionResult
import burp.api.montoya.http.sessions.SessionHandlingActionData
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation
import burp.api.montoya.proxy.websocket.ProxyWebSocket
import burp.api.montoya.websocket.Direction
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import burp.api.montoya.core.HighlightColor
import kotlinx.serialization.json.JsonElement
import java.time.ZonedDateTime
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import io.modelcontextprotocol.kotlin.sdk.server.Server
import java.nio.file.Path
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.encodeHistoryItem
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    // --- Live traffic modifiers: proxy match-and-replace + global header injection.
    // Rules are managed by the tools below; empty registries are a no-op.
    api.proxy().registerRequestHandler(object : ProxyRequestHandler {
        override fun handleRequestReceived(r: InterceptedRequest): ProxyRequestReceivedAction {
            if (!InterceptQueue.enabled) return ProxyRequestReceivedAction.continueWith(r)
            // Park the message and block this proxy thread until an MCP tool decides.
            val pending = InterceptQueue.add(r)
            val decision = try {
                pending.future.get(120, TimeUnit.SECONDS)
            } catch (e: Exception) {
                InterceptQueue.remove(pending.id)
                InterceptDecision.Forward(r)
            }
            return when (decision) {
                is InterceptDecision.Drop -> ProxyRequestReceivedAction.drop()
                is InterceptDecision.Forward -> ProxyRequestReceivedAction.continueWith(decision.request)
            }
        }

        override fun handleRequestToBeSent(r: InterceptedRequest): ProxyRequestToBeSentAction {
            val rules = MatchReplaceRules.all()
            val headers = InjectedHeaders.all()
            if (rules.isEmpty() && headers.isEmpty()) return ProxyRequestToBeSentAction.continueWith(r)
            var request: HttpRequest = r
            if (rules.isNotEmpty()) {
                var text = r.toString()
                for ((match, replace) in rules) {
                    text = try { Regex(match).replace(text, replace) } catch (e: Exception) { text }
                }
                request = HttpRequest.httpRequest(r.httpService(), text)
            }
            for ((name, value) in headers) request = request.withUpdatedHeader(name, value)
            return ProxyRequestToBeSentAction.continueWith(request)
        }
    })

    api.http().registerHttpHandler(object : HttpHandler {
        override fun handleHttpRequestToBeSent(r: HttpRequestToBeSent): RequestToBeSentAction {
            val headers = InjectedHeaders.all()
            if (headers.isEmpty()) return RequestToBeSentAction.continueWith(r)
            var req: HttpRequest = r
            for ((name, value) in headers) req = req.withUpdatedHeader(name, value)
            return RequestToBeSentAction.continueWith(req)
        }

        override fun handleHttpResponseReceived(r: HttpResponseReceived): ResponseReceivedAction =
            ResponseReceivedAction.continueWith(r)
    })

    // Response match-and-replace on proxied responses.
    api.proxy().registerResponseHandler(object : ProxyResponseHandler {
        override fun handleResponseReceived(r: InterceptedResponse): ProxyResponseReceivedAction {
            val rules = ResponseMatchReplaceRules.all()
            if (rules.isEmpty()) return ProxyResponseReceivedAction.continueWith(r)
            var text = r.toString()
            for ((match, replace) in rules) {
                text = try { Regex(match).replace(text, replace) } catch (e: Exception) { text }
            }
            return ProxyResponseReceivedAction.continueWith(HttpResponse.httpResponse(text))
        }

        override fun handleResponseToBeSent(r: InterceptedResponse): ProxyResponseToBeSentAction =
            ProxyResponseToBeSentAction.continueWith(r)
    })

    // Track proxied WebSockets so tools can send messages on them.
    api.proxy().registerWebSocketCreationHandler(object : ProxyWebSocketCreationHandler {
        override fun handleWebSocketCreation(creation: ProxyWebSocketCreation) {
            WebSockets.add(creation.upgradeRequest().url(), creation.proxyWebSocket())
        }
    })

    // A Burp session-handling action that re-applies the MCP-injected headers.
    api.http().registerSessionHandlingAction(object : SessionHandlingAction {
        override fun name(): String = "MCP injected headers"
        override fun performAction(data: SessionHandlingActionData): ActionResult {
            var req = data.request()
            for ((n, v) in InjectedHeaders.all()) req = req.withUpdatedHeader(n, v)
            return ActionResult.actionResult(req)
        }
    })

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        var request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        for ((name, value) in InjectedHeaders.all()) request = request.withUpdatedHeader(name, value)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpUnitTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }

    mcpTool<StartActiveScan>(
        "Starts a Burp active scan (audit) of the given URL using the built-in active audit checks. " +
                "Returns immediately; poll findings later with get_scanner_issues."
    ) {
        val request = HttpRequest.httpRequestFromUrl(url)
        val service = request.httpService()

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(
                service.host(), service.port(), config, request.toString(), api
            )
        }
        if (!allowed) {
            api.logging().logToOutput("MCP active scan denied: $url")
            return@mcpTool "Active scan of $url denied by Burp Suite"
        }

        api.logging().logToOutput("MCP active scan starting: $url")
        val audit = api.scanner().startAudit(
            AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
        )
        audit.addRequest(request)
        val id = ScanRegistry.add("active-audit", url, audit)

        "Started active scan #$id of $url. Poll with scan_status; read findings with get_scanner_issues."
    }

    mcpTool<StartPassiveScan>(
        "Fetches a URL and runs Burp's passive audit checks on the response (no attack traffic sent to the target). " +
                "Read findings with get_scanner_issues."
    ) {
        val request = HttpRequest.httpRequestFromUrl(url)
        val service = request.httpService()
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(
                service.host(), service.port(), config, request.toString(), api
            )
        }
        if (!allowed) return@mcpTool "Passive scan of $url denied by Burp Suite"

        val audit = api.scanner().startAudit(
            AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS)
        )
        audit.addRequest(request)
        val id = ScanRegistry.add("passive-audit", url, audit)
        "Started passive scan #$id of $url."
    }

    mcpTool(
        "scan_status",
        "Reports live status (running/finished, request and error counts) of every scan/crawl task started this session."
    ) {
        val tasks = ScanRegistry.all()
        if (tasks.isEmpty()) "No scan or crawl tasks have been started this session."
        else tasks.joinToString("\n") { entry ->
            // Some ScanTask methods may be unimplemented in the running Burp build; guard each.
            val status = runCatching { entry.task.statusMessage() }.getOrElse { "n/a" }
            val reqs = runCatching { entry.task.requestCount() }.getOrNull()
            val errs = runCatching { entry.task.errorCount() }.getOrNull()
            buildString {
                append("#${entry.id} [${entry.kind}] ${entry.target} -> ").append(status)
                if (reqs != null) append(" | requests=").append(reqs)
                if (errs != null) append(" | errors=").append(errs)
            }
        }
    }

    mcpTool<ExportScanReport>(
        "Exports all current scanner issues to an HTML or XML report file at the given absolute path. format: HTML or XML."
    ) {
        val fmt = if (format.equals("XML", ignoreCase = true)) ReportFormat.XML else ReportFormat.HTML
        val all = api.siteMap().issues()
        val fr = filterRegex
        val issues = if (fr.isNullOrBlank()) all else {
            val p = runCatching { Regex(fr, RegexOption.IGNORE_CASE) }.getOrNull()
                ?: return@mcpTool "Invalid filterRegex."
            all.filter { p.containsMatchIn("${it.name()} ${it.baseUrl()} ${it.severity()}") }
        }
        if (issues.isEmpty()) return@mcpTool "No scanner issues to export (after filter)."
        api.scanner().generateReport(issues, fmt, Path.of(path))
        "Exported ${issues.size} issue(s) as ${fmt.name} to $path"
    }

    mcpTool<StartCrawl>(
        "Starts a Burp crawl (spider) from one or more seed URLs (comma-separated). Burp discovers " +
                "linked content and adds it to the site map. Combine with start_active_scan to audit what is found."
    ) {
        val seeds = url.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        if (seeds.isEmpty()) return@mcpTool "No seed URLs provided"

        for (seed in seeds) {
            val request = HttpRequest.httpRequestFromUrl(seed)
            val service = request.httpService()
            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(
                    service.host(), service.port(), config, request.toString(), api
                )
            }
            if (!allowed) {
                api.logging().logToOutput("MCP crawl denied: $seed")
                return@mcpTool "Crawl of $seed denied by Burp Suite"
            }
        }

        api.logging().logToOutput("MCP crawl starting: $seeds")
        val crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(*seeds.toTypedArray()))
        val id = ScanRegistry.add("crawl", seeds.joinToString(","), crawl)

        "Started crawl #$id from ${seeds.size} seed(s): ${seeds.joinToString(", ")}. " +
                "Discovered content appears in the site map (get_site_map); poll scan_status; then start_active_scan."
    }

    // ---------------- Site map ----------------
    mcpPaginatedTool<GetSiteMap, String>(
        "Lists site map entries (method, URL, status), optionally filtered to a URL prefix. Paginated via count/offset."
    ) {
        val entries = if (prefix.isNullOrBlank()) api.siteMap().requestResponses()
        else api.siteMap().requestResponses(burp.api.montoya.sitemap.SiteMapFilter.prefixFilter(prefix))
        entries.map { rr ->
            val status = rr.response()?.statusCode()?.toString() ?: "-"
            "${rr.request().method()} ${rr.request().url()} -> $status"
        }
    }

    mcpTool<AddToSiteMap>("Fetches a URL and adds the request/response to Burp's site map.") {
        val request = HttpRequest.httpRequestFromUrl(url)
        val service = request.httpService()
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(
                service.host(), service.port(), config, request.toString(), api
            )
        }
        if (!allowed) return@mcpTool "Adding $url denied by Burp Suite"
        val rr = api.http().sendRequest(request)
        api.siteMap().add(rr)
        "Added to site map: $url (${rr.response()?.statusCode() ?: "-"})"
    }

    // ---------------- Scope ----------------
    mcpTool<ScopeAdd>("Adds a URL prefix to Burp's target scope.") {
        api.scope().includeInScope(url)
        "Added to scope: $url"
    }
    mcpTool<ScopeRemove>("Removes a URL from Burp's target scope.") {
        api.scope().excludeFromScope(url)
        "Removed from scope: $url"
    }
    mcpTool<ScopeCheck>("Checks whether a URL is in Burp's target scope.") {
        "In scope: ${api.scope().isInScope(url)}"
    }

    // ---------------- Intruder replacement: real sniper fuzzing with results ----------------
    mcpTool<RunIntruderAttack>(
        "Runs an automated sniper-style attack: replaces the marker (default FUZZ) in the request content with each " +
                "payload, sends every request through Burp, and returns status code, response length and time per payload. " +
                "This is the automatable equivalent of Intruder (Montoya cannot run the Intruder UI attack itself)."
    ) {
        val mark = if (marker.isNullOrEmpty()) "FUZZ" else marker
        val list = payloads.take(1000)
        if (list.isEmpty()) return@mcpTool "No payloads provided."

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) return@mcpTool "Attack against $targetHostname:$targetPort denied by Burp Suite"

        val header = "payload | status | length | ms"
        val rows = list.map { payload ->
            val body = normalizeHttpContent(content.replace(mark, payload))
            val request = HttpRequest.httpRequest(toMontoyaService(), body)
            val start = System.currentTimeMillis()
            val resp = api.http().sendRequest(request)
            val ms = System.currentTimeMillis() - start
            val code = resp?.response()?.statusCode()?.toString() ?: "-"
            val len = resp?.response()?.toByteArray()?.length()?.toString() ?: "-"
            val shown = if (payload.length > 40) payload.take(40) + "…" else payload
            "$shown | $code | $len | $ms"
        }
        (listOf("Sniper attack: ${list.size} requests to $targetHostname:$targetPort", header) + rows)
            .joinToString("\n")
    }

    // ---------------- Decoder extras ----------------
    mcpTool<HexEncode>("Hex-encodes the input string (UTF-8 bytes).") {
        content.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }
    }
    mcpTool<HexDecode>("Hex-decodes the input string to text (UTF-8).") {
        val clean = content.trim().replace(" ", "").replace("\n", "")
        String(ByteArray(clean.length / 2) { i -> clean.substring(i * 2, i * 2 + 2).toInt(16).toByte() },
            Charsets.UTF_8)
    }
    mcpTool<HtmlEncode>("HTML-entity-encodes the input string.") {
        api.utilities().htmlUtils().encode(content)
    }
    mcpTool<HtmlDecode>("HTML-entity-decodes the input string.") {
        api.utilities().htmlUtils().decode(content)
    }
    mcpTool<GzipCompress>("Gzip-compresses the input text and returns the result base64-encoded.") {
        val compressed = api.utilities().compressionUtils()
            .compress(burp.api.montoya.core.ByteArray.byteArray(content), CompressionType.GZIP)
        api.utilities().base64Utils().encodeToString(compressed)
    }
    mcpTool<GzipDecompress>("Gzip-decompresses base64-encoded gzip data and returns the resulting text.") {
        val raw = api.utilities().base64Utils().decode(content)
        val out = api.utilities().compressionUtils().decompress(raw, CompressionType.GZIP)
        out.toString()
    }

    // ---------------- Custom scan checks (BCheck) ----------------
    mcpTool<ImportBcheck>(
        "Imports a BCheck script into Burp's scanner. Once imported it runs as a custom scan check on subsequent " +
                "audits. Returns the import status and any parse errors."
    ) {
        val result = api.scanner().bChecks().importBCheck(script, enabled)
        val errors = result.importErrors()
        buildString {
            append("BCheck import status: ").append(result.status())
            if (errors.isNotEmpty()) append("\nErrors:\n").append(errors.joinToString("\n") { "  - $it" })
            else append("\nImported successfully; it will run on future scans.")
        }
    }

    // ---------------- Proxy match-and-replace ----------------
    mcpTool<AddMatchReplaceRule>(
        "Adds a regex match-and-replace rule applied to requests as they leave the Proxy (browser traffic). " +
                "match is a Java regex over the full request text; replace is the replacement (supports \$1 groups)."
    ) {
        MatchReplaceRules.add(match, replace)
        "Added match-and-replace rule #${MatchReplaceRules.all().size}: /$match/ -> \"$replace\". " +
                "Applies to proxied requests."
    }
    mcpTool("list_match_replace_rules", "Lists the active proxy match-and-replace rules.") {
        val rules = MatchReplaceRules.all()
        if (rules.isEmpty()) "No match-and-replace rules configured."
        else rules.mapIndexed { i, (m, r) -> "#${i + 1}: /$m/ -> \"$r\"" }.joinToString("\n")
    }
    mcpTool("clear_match_replace_rules", "Removes all proxy match-and-replace rules.") {
        val n = MatchReplaceRules.all().size
        MatchReplaceRules.clear()
        "Cleared $n match-and-replace rule(s)."
    }

    // ---------------- Global request-header injection (session-handling style) ----------------
    mcpTool<AddRequestHeader>(
        "Injects (or overwrites) a header on every HTTP request Burp sends, across all tools. Useful for adding an " +
                "Authorization or session header to authenticate all traffic."
    ) {
        InjectedHeaders.add(name, value)
        "Now injecting header on all requests: $name: $value (${InjectedHeaders.all().size} header(s) active)."
    }
    mcpTool("list_request_headers", "Lists the headers currently injected into all outgoing requests.") {
        val headers = InjectedHeaders.all()
        if (headers.isEmpty()) "No injected headers."
        else headers.joinToString("\n") { (n, v) -> "$n: $v" }
    }
    mcpTool("clear_request_headers", "Stops injecting all previously added request headers.") {
        val n = InjectedHeaders.all().size
        InjectedHeaders.clear()
        "Cleared $n injected header(s)."
    }

    // ---------------- Scanner: audit site map + combined + custom issue ----------------
    mcpTool<AuditSiteMap>(
        "Starts an active audit of every request currently in the site map (optionally in-scope only). " +
                "Run start_crawl first to populate the site map."
    ) {
        val audit = api.scanner().startAudit(
            AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
        )
        var n = 0
        for (rr in api.siteMap().requestResponses()) {
            val url = rr.request().url()
            if (inScopeOnly && !api.scope().isInScope(url)) continue
            audit.addRequest(rr.request()); n++
        }
        val id = ScanRegistry.add("audit-sitemap", "$n entries", audit)
        "Started audit #$id of $n site-map entries. Poll scan_status; read get_scanner_issues."
    }

    mcpTool<CrawlAndAudit>(
        "Convenience: starts a crawl from the seed URL, then you audit the discovered content with audit_site_map " +
                "once the crawl finishes (Montoya has no single combined call)."
    ) {
        val crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(url))
        val id = ScanRegistry.add("crawl", url, crawl)
        "Started crawl #$id from $url. When scan_status shows it finished, call audit_site_map to audit everything found."
    }

    mcpTool<ReportIssue>(
        "Adds a custom audit issue to the site map. severity: HIGH|MEDIUM|LOW|INFORMATION; " +
                "confidence: CERTAIN|FIRM|TENTATIVE."
    ) {
        val sev = runCatching { AuditIssueSeverity.valueOf(severity.uppercase()) }.getOrDefault(AuditIssueSeverity.INFORMATION)
        val conf = runCatching { AuditIssueConfidence.valueOf(confidence.uppercase()) }.getOrDefault(AuditIssueConfidence.TENTATIVE)
        val issue = AuditIssue.auditIssue(
            name, detail, "", baseUrl, sev, conf, "", "", sev, emptyList<HttpRequestResponse>()
        )
        api.siteMap().add(issue)
        "Added issue '$name' ($sev/$conf) at $baseUrl to the site map."
    }

    // ---------------- Proxy: response match-and-replace ----------------
    mcpTool<AddResponseMatchReplaceRule>(
        "Adds a regex match-and-replace rule applied to proxied responses (server -> browser). " +
                "match is a Java regex over the full response text; replace supports \$1 groups."
    ) {
        ResponseMatchReplaceRules.add(match, replace)
        "Added response rule #${ResponseMatchReplaceRules.all().size}: /$match/ -> \"$replace\"."
    }
    mcpTool("list_response_match_replace_rules", "Lists active response match-and-replace rules.") {
        val rules = ResponseMatchReplaceRules.all()
        if (rules.isEmpty()) "No response match-and-replace rules."
        else rules.mapIndexed { i, (m, r) -> "#${i + 1}: /$m/ -> \"$r\"" }.joinToString("\n")
    }
    mcpTool("clear_response_match_replace_rules", "Removes all response match-and-replace rules.") {
        val n = ResponseMatchReplaceRules.all().size
        ResponseMatchReplaceRules.clear()
        "Cleared $n response rule(s)."
    }

    // ---------------- Proxy: live intercept queue ----------------
    mcpTool<InterceptQueueEnable>(
        "Enables or disables the MCP intercept queue. When enabled, proxied requests are paused and must be " +
                "released with intercept_forward or intercept_drop (auto-forwarded after 120s)."
    ) {
        InterceptQueue.enabled = enabled
        if (!enabled) InterceptQueue.releaseAllForward()
        "Intercept queue " + if (enabled) "ENABLED (requests will pause)." else "DISABLED (pending released)."
    }
    mcpTool("intercept_queue_list", "Lists paused requests waiting in the intercept queue.") {
        val pending = InterceptQueue.list()
        if (pending.isEmpty()) "No paused requests."
        else pending.joinToString("\n\n") { "#${it.id} ${it.summary}\n${it.request}" }
    }
    mcpTool<InterceptForward>(
        "Forwards a paused request by id. Optionally provide modified raw request content to replace it."
    ) {
        val p = InterceptQueue.get(id) ?: return@mcpTool "No paused request #$id"
        val request = if (content.isNullOrBlank()) p.request
        else HttpRequest.httpRequest(p.request.httpService(), normalizeHttpContent(content))
        InterceptQueue.resolve(id, InterceptDecision.Forward(request))
        "Forwarded request #$id" + if (content.isNullOrBlank()) "." else " (modified)."
    }
    mcpTool<InterceptDrop>("Drops a paused request by id.") {
        if (InterceptQueue.get(id) == null) return@mcpTool "No paused request #$id"
        InterceptQueue.resolve(id, InterceptDecision.Drop)
        "Dropped request #$id."
    }

    // ---------------- WebSockets ----------------
    mcpTool("list_websockets", "Lists proxied WebSocket connections seen since load.") {
        val ws = WebSockets.list()
        if (ws.isEmpty()) "No WebSocket connections observed."
        else ws.joinToString("\n") { "#${it.first}: ${it.second}" }
    }
    mcpTool<SendWebSocketMessage>(
        "Sends a text message on a proxied WebSocket by id. direction: to_server (client->server) or to_client."
    ) {
        val ws = WebSockets.get(id) ?: return@mcpTool "No WebSocket #$id"
        val dir = if (direction.equals("to_client", true) || direction.equals("server_to_client", true))
            Direction.SERVER_TO_CLIENT else Direction.CLIENT_TO_SERVER
        ws.sendTextMessage(message, dir)
        "Sent ${message.length}-char message on WebSocket #$id ($dir)."
    }

    // ---------------- Cookie jar ----------------
    mcpTool("get_cookies", "Lists cookies in Burp's cookie jar.") {
        val cookies = api.http().cookieJar().cookies()
        if (cookies.isEmpty()) "Cookie jar is empty."
        else cookies.joinToString("\n") { "${it.name()}=${it.value()} ; domain=${it.domain()} ; path=${it.path()}" }
    }
    mcpTool<SetCookie>(
        "Adds/updates a cookie in Burp's cookie jar. expiry is optional ISO-8601 " +
                "(e.g. 2027-01-01T00:00:00Z); omit for a session cookie."
    ) {
        val exp = expiry?.takeIf { it.isNotBlank() }?.let {
            runCatching { ZonedDateTime.parse(it) }.getOrNull()
        }
        api.http().cookieJar().setCookie(name, value, path ?: "/", domain, exp)
        "Set cookie $name for domain $domain" + if (exp != null) " (expires $exp)." else " (session)."
    }

    // ---------------- Response comparison (partial Comparer) ----------------
    mcpTool<CompareResponses>(
        "Fetches each URL and reports which response attributes vary vs stay invariant across them " +
                "(status, length, word/line counts, etc.) — useful for oracle/diffing."
    ) {
        val urls = url.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        if (urls.size < 2) return@mcpTool "Provide at least two comma-separated URLs."
        val analyzer = api.http().createResponseVariationsAnalyzer()
        var count = 0
        for (u in urls) {
            val allowed = runBlocking {
                val req = HttpRequest.httpRequestFromUrl(u)
                HttpRequestSecurity.checkHttpRequestPermission(req.httpService().host(), req.httpService().port(), config, req.toString(), api)
            }
            if (!allowed) continue
            api.http().sendRequest(HttpRequest.httpRequestFromUrl(u)).response()?.let { analyzer.updateWith(it); count++ }
        }
        "Compared $count responses.\nVariant attributes: ${analyzer.variantAttributes()}\n" +
                "Invariant attributes: ${analyzer.invariantAttributes()}"
    }

    // ---------------- Codecs: deflate, hashes, JSON ----------------
    mcpTool<DeflateCompress>("Deflate-compresses text and returns base64.") {
        val c = api.utilities().compressionUtils()
            .compress(burp.api.montoya.core.ByteArray.byteArray(content), CompressionType.DEFLATE)
        api.utilities().base64Utils().encodeToString(c)
    }
    mcpTool<DeflateDecompress>("Deflate-decompresses base64 data and returns text.") {
        val raw = api.utilities().base64Utils().decode(content)
        api.utilities().compressionUtils().decompress(raw, CompressionType.DEFLATE).toString()
    }
    mcpTool<HashDigest>(
        "Computes a cryptographic digest of the input. algorithm e.g. MD5, SHA_1, SHA_256, SHA_512. Returns hex."
    ) {
        val algo = runCatching { DigestAlgorithm.valueOf(algorithm.uppercase().replace("-", "_")) }
            .getOrDefault(DigestAlgorithm.SHA_256)
        val digest = api.utilities().cryptoUtils()
            .generateDigest(burp.api.montoya.core.ByteArray.byteArray(content), algo)
        (0 until digest.length()).joinToString("") { "%02x".format(digest.getByte(it)) }
    }
    mcpTool<JsonPretty>("Pretty-prints (indents) a JSON string.") {
        val el = Json.parseToJsonElement(content)
        Json { prettyPrint = true }.encodeToString(JsonElement.serializer(), el)
    }
    mcpTool<JsonMinify>("Minifies a JSON string (removes whitespace).") {
        val el = Json.parseToJsonElement(content)
        Json.encodeToString(JsonElement.serializer(), el)
    }

    // ---------------- Batch send (parallel) ----------------
    mcpTool<BatchSend>(
        "Sends many URLs in parallel through Burp and returns status + length per URL " +
                "(comma- or newline-separated). Much faster than sending one at a time."
    ) {
        val list = urls.split(Regex("[,\\n]+")).map { it.trim() }.filter { it.isNotEmpty() }
        if (list.isEmpty()) return@mcpTool "No URLs provided."
        val requests = mutableListOf<HttpRequest>()
        val kept = mutableListOf<String>()
        for (u in list) {
            val req = HttpRequest.httpRequestFromUrl(u)
            val ok = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(req.httpService().host(), req.httpService().port(), config, req.toString(), api)
            }
            if (ok) { requests.add(req); kept.add(u) }
        }
        if (requests.isEmpty()) return@mcpTool "All URLs denied by Burp Suite."
        val start = System.currentTimeMillis()
        val results = api.http().sendRequests(requests)
        val ms = System.currentTimeMillis() - start
        val rows = results.mapIndexed { i, rr ->
            "${kept.getOrElse(i) { "?" }} -> ${rr.response()?.statusCode() ?: "-"} " +
                    "(${rr.response()?.toByteArray()?.length() ?: 0} bytes)"
        }
        "Sent ${requests.size} request(s) in ${ms}ms:\n" + rows.joinToString("\n")
    }

    // ---------------- Organizer ----------------
    mcpTool<SendToOrganizer>("Fetches a URL and sends its request/response to Burp's Organizer, with an optional note.") {
        val req = HttpRequest.httpRequestFromUrl(url)
        val ok = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(req.httpService().host(), req.httpService().port(), config, req.toString(), api)
        }
        if (!ok) return@mcpTool "Request to $url denied by Burp Suite"
        var rr = api.http().sendRequest(req)
        if (!note.isNullOrBlank()) rr = rr.withAnnotations(rr.annotations().withNotes(note))
        api.organizer().sendToOrganizer(rr)
        "Sent $url to Organizer" + if (note.isNullOrBlank()) "." else " with note."
    }

    // ---------------- JWT ----------------
    mcpTool<JwtDecode>(
        "Decodes a JWT: base64url-decodes the header and payload. Does NOT verify the signature."
    ) {
        val parts = token.trim().split(".")
        if (parts.size < 2) return@mcpTool "Not a JWT (expected header.payload.signature)."
        fun dec(s: String): String = try {
            String(java.util.Base64.getUrlDecoder().decode(s), Charsets.UTF_8)
        } catch (e: Exception) { "<decode error: ${e.message}>" }
        buildString {
            append("HEADER:\n").append(dec(parts[0])).append("\n\n")
            append("PAYLOAD:\n").append(dec(parts[1]))
            if (parts.size > 2) append("\n\nSIGNATURE (base64url, not verified):\n").append(parts[2])
        }
    }

    // ---------------- JSON path read/edit ----------------
    mcpTool<JsonRead>("Reads a value from a JSON string at the given path using Burp's jsonUtils (e.g. path 'user.id').") {
        api.utilities().jsonUtils().read(json, path) ?: "(no value at '$path')"
    }
    mcpTool<JsonEdit>(
        "Edits a JSON string using Burp's jsonUtils. operation: add | update | remove. " +
                "value is required for add and update."
    ) {
        val u = api.utilities().jsonUtils()
        when (operation.lowercase()) {
            "add" -> u.add(json, path, value ?: "")
            "update" -> u.update(json, path, value ?: "")
            "remove" -> u.remove(json, path)
            else -> "Unknown operation '$operation' (use add|update|remove)"
        }
    }

    // ---------------- Active WebSocket (open a new connection) ----------------
    mcpTool<CreateWebSocket>(
        "Opens a NEW WebSocket to a target (not just proxied ones) and optionally sends an initial text message. " +
                "Returns a websocket id for send_active_websocket_message."
    ) {
        val service = HttpService.httpService(host, port, tls)
        val allowed = runBlocking { HttpRequestSecurity.checkHttpRequestPermission(host, port, config, "GET $path", api) }
        if (!allowed) return@mcpTool "WebSocket to $host:$port denied by Burp Suite"
        val creation = api.websockets().createWebSocket(service, path)
        if (creation.status() != ExtensionWebSocketCreationStatus.SUCCESS || creation.webSocket().isEmpty) {
            return@mcpTool "WebSocket creation failed: ${creation.status()}"
        }
        val ws = creation.webSocket().get()
        val id = ActiveWebSockets.add("$host:$port$path", ws)
        if (!message.isNullOrEmpty()) ws.sendTextMessage(message)
        "Opened active WebSocket #$id to $host:$port$path" + if (!message.isNullOrEmpty()) " and sent initial message." else "."
    }
    mcpTool<SendActiveWebSocketMessage>("Sends a text message on an active (extension-created) WebSocket by id.") {
        val ws = ActiveWebSockets.get(id) ?: return@mcpTool "No active WebSocket #$id"
        ws.sendTextMessage(message)
        "Sent ${message.length}-char message on active WebSocket #$id."
    }

    // ---------------- Response comparison by keywords ----------------
    mcpTool<CompareResponsesKeywords>(
        "Fetches each URL and reports which of the given keywords vary vs stay constant across responses " +
                "(keywords comma-separated). Complements compare_responses."
    ) {
        val urlList = url.split(Regex("[,\\n]+")).map { it.trim() }.filter { it.isNotEmpty() }
        val kw = keywords.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        if (urlList.size < 2 || kw.isEmpty()) return@mcpTool "Provide >=2 URLs and >=1 keyword."
        val analyzer = api.http().createResponseKeywordsAnalyzer(kw)
        var count = 0
        for (u in urlList) {
            api.http().sendRequest(HttpRequest.httpRequestFromUrl(u)).response()?.let { analyzer.updateWith(it); count++ }
        }
        "Compared $count responses for keywords $kw.\nVariant (present in some, not others): ${analyzer.variantKeywords()}\n" +
                "Invariant (same across all): ${analyzer.invariantKeywords()}"
    }

    // ---------------- Annotate proxy history ----------------
    mcpTool<AnnotateHistory>(
        "Adds a note and/or highlight color to a proxy-history item by index (from get_proxy_http_history). " +
                "color: NONE|RED|ORANGE|YELLOW|GREEN|CYAN|BLUE|PINK|MAGENTA|GRAY."
    ) {
        val history = api.proxy().history()
        if (index < 0 || index >= history.size) return@mcpTool "No history item #$index (size ${history.size})."
        val ann = history[index].annotations()
        val c = color
        if (!note.isNullOrBlank()) ann.setNotes(note)
        if (!c.isNullOrBlank()) runCatching { ann.setHighlightColor(HighlightColor.valueOf(c.uppercase())) }
        "Annotated history #$index (${history[index].request().url()})."
    }

    // ---------------- Burp info + random ----------------
    mcpTool("burp_info", "Returns Burp Suite version, edition and build info.") {
        val v = api.burpSuite().version()
        "${v.name()} ${v.major()}.${v.minor()} (build ${v.build()}, #${v.buildNumber()}) — ${v.edition()}"
    }
    mcpTool<RandomBytes>("Generates N cryptographically-random bytes, returned as hex.") {
        val b = ByteArray(length.coerceIn(1, 4096))
        java.security.SecureRandom().nextBytes(b)
        b.joinToString("") { "%02x".format(it) }
    }
    mcpTool<RandomNumber>("Returns a random integer in [min, max].") {
        if (max < min) return@mcpTool "max must be >= min."
        (min + java.security.SecureRandom().nextInt((max - min) + 1)).toString()
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class StartActiveScan(val url: String)

@Serializable
data class StartCrawl(val url: String)

@Serializable
data class StartPassiveScan(val url: String)

@Serializable
data class ExportScanReport(val path: String, val format: String, val filterRegex: String? = null)

@Serializable
data class GetSiteMap(val prefix: String? = null, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class AddToSiteMap(val url: String)

@Serializable
data class ScopeAdd(val url: String)

@Serializable
data class ScopeRemove(val url: String)

@Serializable
data class ScopeCheck(val url: String)

@Serializable
data class RunIntruderAttack(
    val content: String,
    val marker: String? = null,
    val payloads: List<String>,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class HexEncode(val content: String)

@Serializable
data class HexDecode(val content: String)

@Serializable
data class HtmlEncode(val content: String)

@Serializable
data class HtmlDecode(val content: String)

@Serializable
data class GzipCompress(val content: String)

@Serializable
data class GzipDecompress(val content: String)

@Serializable
data class ImportBcheck(val script: String, val enabled: Boolean = true)

@Serializable
data class AddMatchReplaceRule(val match: String, val replace: String)

@Serializable
data class AddRequestHeader(val name: String, val value: String)

/** Regex match-and-replace rules applied to proxied requests. */
object MatchReplaceRules {
    private val rules = mutableListOf<Pair<String, String>>()
    @Synchronized fun add(match: String, replace: String) { rules.add(match to replace) }
    @Synchronized fun all(): List<Pair<String, String>> = rules.toList()
    @Synchronized fun clear() { rules.clear() }
}

/** Headers injected into every outgoing HTTP request. */
object InjectedHeaders {
    private val headers = mutableListOf<Pair<String, String>>()
    @Synchronized fun add(name: String, value: String) {
        headers.removeAll { it.first.equals(name, ignoreCase = true) }
        headers.add(name to value)
    }
    @Synchronized fun all(): List<Pair<String, String>> = headers.toList()
    @Synchronized fun clear() { headers.clear() }
}

@Serializable
data class AuditSiteMap(val inScopeOnly: Boolean = false)

@Serializable
data class CrawlAndAudit(val url: String)

@Serializable
data class ReportIssue(
    val name: String, val detail: String, val severity: String, val confidence: String, val baseUrl: String
)

@Serializable
data class AddResponseMatchReplaceRule(val match: String, val replace: String)

@Serializable
data class InterceptQueueEnable(val enabled: Boolean)

@Serializable
data class InterceptForward(val id: Int, val content: String? = null)

@Serializable
data class InterceptDrop(val id: Int)

@Serializable
data class SendWebSocketMessage(val id: Int, val direction: String, val message: String)

@Serializable
data class SetCookie(
    val name: String, val value: String, val domain: String,
    val path: String? = null, val expiry: String? = null
)

@Serializable
data class CompareResponses(val url: String)

@Serializable
data class DeflateCompress(val content: String)

@Serializable
data class DeflateDecompress(val content: String)

@Serializable
data class HashDigest(val algorithm: String, val content: String)

@Serializable
data class JsonPretty(val content: String)

@Serializable
data class JsonMinify(val content: String)

@Serializable
data class BatchSend(val urls: String)

@Serializable
data class SendToOrganizer(val url: String, val note: String? = null)

@Serializable
data class JwtDecode(val token: String)

@Serializable
data class JsonRead(val json: String, val path: String)

@Serializable
data class JsonEdit(val json: String, val path: String, val operation: String, val value: String? = null)

@Serializable
data class CreateWebSocket(
    val host: String, val port: Int, val path: String,
    val tls: Boolean = false, val message: String? = null
)

@Serializable
data class SendActiveWebSocketMessage(val id: Int, val message: String)

@Serializable
data class CompareResponsesKeywords(val url: String, val keywords: String)

@Serializable
data class AnnotateHistory(val index: Int, val note: String? = null, val color: String? = null)

@Serializable
data class RandomBytes(val length: Int)

@Serializable
data class RandomNumber(val min: Int, val max: Int)

/** Extension-created (active) WebSockets, addressable by id. */
object ActiveWebSockets {
    private val sockets = ConcurrentHashMap<Int, Pair<String, ExtensionWebSocket>>()
    private val counter = AtomicInteger()
    fun add(url: String, ws: ExtensionWebSocket): Int {
        val id = counter.incrementAndGet()
        sockets[id] = url to ws
        return id
    }
    fun get(id: Int): ExtensionWebSocket? = sockets[id]?.second
}

/** Regex match-and-replace rules applied to proxied responses. */
object ResponseMatchReplaceRules {
    private val rules = mutableListOf<Pair<String, String>>()
    @Synchronized fun add(match: String, replace: String) { rules.add(match to replace) }
    @Synchronized fun all(): List<Pair<String, String>> = rules.toList()
    @Synchronized fun clear() { rules.clear() }
}

sealed class InterceptDecision {
    data class Forward(val request: burp.api.montoya.http.message.requests.HttpRequest) : InterceptDecision()
    object Drop : InterceptDecision()
}

/** Holds proxied requests paused for manual forward/drop over MCP. */
object InterceptQueue {
    @Volatile var enabled = false

    class Pending(
        val id: Int,
        val summary: String,
        val request: burp.api.montoya.http.message.requests.HttpRequest,
        val future: CompletableFuture<InterceptDecision>
    )

    private val pending = ConcurrentHashMap<Int, Pending>()
    private val counter = AtomicInteger()

    fun add(request: burp.api.montoya.http.message.requests.HttpRequest): Pending {
        val id = counter.incrementAndGet()
        val p = Pending(id, "${request.method()} ${request.url()}", request, CompletableFuture())
        pending[id] = p
        return p
    }

    fun list(): List<Pending> = pending.values.sortedBy { it.id }
    fun get(id: Int): Pending? = pending[id]
    fun remove(id: Int) { pending.remove(id) }

    fun resolve(id: Int, decision: InterceptDecision): Boolean {
        val p = pending.remove(id) ?: return false
        p.future.complete(decision)
        return true
    }

    fun releaseAllForward() {
        pending.values.toList().forEach { it.future.complete(InterceptDecision.Forward(it.request)) }
        pending.clear()
    }
}

/** Tracks proxied WebSocket connections so tools can send messages. */
object WebSockets {
    private val sockets = ConcurrentHashMap<Int, Pair<String, ProxyWebSocket>>()
    private val counter = AtomicInteger()
    fun add(url: String, ws: ProxyWebSocket): Int {
        val id = counter.incrementAndGet()
        sockets[id] = url to ws
        return id
    }
    fun get(id: Int): ProxyWebSocket? = sockets[id]?.second
    fun list(): List<Pair<Int, String>> = sockets.entries.sortedBy { it.key }.map { it.key to it.value.first }
}

/** Tracks scan/crawl tasks started this session so scan_status can report on them. */
object ScanRegistry {
    data class Entry(val id: Int, val kind: String, val target: String, val task: ScanTask)

    private val entries = mutableListOf<Entry>()
    private var counter = 0

    @Synchronized
    fun add(kind: String, target: String, task: ScanTask): Int {
        val id = counter++
        entries.add(Entry(id, kind, target, task))
        return id
    }

    @Synchronized
    fun all(): List<Entry> = entries.toList()
}

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
