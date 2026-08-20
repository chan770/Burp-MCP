# Burp-MCP

> **Built on top of [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server).**
> This project is a derivative work of PortSwigger's official Burp MCP server and
> would not exist without it. All original code, architecture, and the ktor +
> MCP-SDK transport are theirs; this repo keeps that foundation and adds new tools.
> Full credit to PortSwigger. Licensed under GPLv3, same as upstream.

An extended **Model Context Protocol (MCP) server** for Burp Suite, exposing far
more of Burp to AI clients (Claude Desktop, Claude Code, etc.) than the stock
server — start scans and crawls, drive the site map and scope, run automated
sniper fuzzing, import custom BCheck scan checks, rewrite live traffic, and more.

> For **authorized security testing only.**

## What this adds over the stock server

| Area | Added tools |
|------|-------------|
| **Scanner** | `start_active_scan`, `start_passive_scan`, `start_crawl`, `crawl_and_audit`, `audit_site_map`, `scan_status`, `export_scan_report` (HTML/XML), `report_issue` |
| **Target** | `get_site_map`, `add_to_site_map`, `scope_add`, `scope_remove`, `scope_check` |
| **Intruder** | `run_intruder_attack` — real sniper fuzzing (marker + payloads → status/length/time per request) |
| **Custom checks** | `import_bcheck` — load a BCheck at runtime; runs on subsequent audits |
| **Live traffic** | request & response `*_match_replace_rule` (add/list/clear); `add_request_header` / `list` / `clear` (global header injection); live intercept queue (`intercept_queue_enable`, `intercept_queue_list`, `intercept_forward`, `intercept_drop`); `list_websockets`, `send_web_socket_message` |
| **Session/state** | `get_cookies`, `set_cookie`, plus a registered "MCP injected headers" session-handling action |
| **Analysis** | `compare_responses` (attributes), `compare_responses_keywords` (keywords) |
| **Throughput** | `batch_send` — send many URLs in parallel |
| **WebSockets** | `list_websockets`, `send_web_socket_message`, `create_web_socket`, `send_active_web_socket_message`, `get_web_socket_messages` (read captured traffic) |
| **Scanner events** | `get_new_scanner_issues` (issues since last poll) |
| **Organizer / history** | `send_to_organizer`, `annotate_history` (note + highlight) |
| **Data / parsing** | `parse_request`, `base64url_encode/decode`, `json_validate`, `regex_extract`, `text_diff`, `convert_number`, `string_transform` |
| **Persistence** | `kv_set` / `kv_get` / `kv_list` / `kv_delete` (project or user scope) |
| **Engine / misc** | `pause_tasks`, `resume_tasks`, `burp_info`, `burp_command_line`, `burp_shutdown`, `random_bytes`, `random_number` |
| **Decoder** | `hex`, `html`, `gzip`, `deflate` encode/decode; `hash_digest` (MD5/SHA-*); `json_pretty` / `json_minify`; `json_read` / `json_edit` (path-based); `jwt_decode` |

All of the stock server's tools (proxy history, HTTP/1.1 & HTTP/2 send, repeater/intruder
hand-off, collaborator, encoders, options, editor) remain available.

### Honest limitations (Montoya API boundaries)

The Montoya API cannot do these, so they are intentionally not faked: native
Intruder attack execution / result reading, reading Repeater tab responses, live
intercept forward-drop editing, managing other extensions, Sequencer, Comparer,
the unified Logger view, session-handling rules, and project save/load.
`run_intruder_attack` and `send_http1_request` are the practical substitutes.

## Build

Requires JDK 21 (the Gradle toolchain resolver will fetch it).

```bash
./gradlew shadowJar embedProxyJar
```

Output: `build/libs/burp-mcp-all.jar` (self-contained, with the stdio proxy embedded).

> On Windows, build from a normal directory (not `%TEMP%`) to avoid a Kotlin
> incremental-compile file-lock; this repo sets `kotlin.incremental=false`.

## Install in Burp

1. Burp → **Extensions → Installed → Add** → Type **Java** → select `burp-mcp-all.jar`.
2. Open the **MCP** tab. Note the SSE URL (default `http://127.0.0.1:9876`).
3. Click **Install to Claude Desktop** (writes the proxy entry to
   `claude_desktop_config.json`), then restart Claude Desktop.
   For Claude Code: `claude mcp add --transport http burp http://127.0.0.1:9876/mcp`.

## Example workflow (over MCP)

```
scope_add            http://target/
start_crawl          http://target/
get_site_map         prefix=http://target
start_active_scan    http://target/search?q=test
scan_status
get_scanner_issues
export_scan_report   path=report.html format=HTML
run_intruder_attack  content="GET /profile?id=FUZZ HTTP/1.1..." payloads=["0","1","2"]
```

## Credits

This project is **built on top of [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)**
by [PortSwigger](https://portswigger.net/). The base extension — its Montoya
integration, ktor server, the `io.modelcontextprotocol` Kotlin SDK transport,
the Claude Desktop installer, and the original tool set — is entirely their work.
This repository only adds extra tools on top. Huge thanks to the PortSwigger team.

## License

GPLv3 — see [LICENSE](LICENSE). This is a derivative work of PortSwigger's
`mcp-server` (also GPLv3); their copyright and license are retained. See
[NOTICE](NOTICE) for attribution details.
