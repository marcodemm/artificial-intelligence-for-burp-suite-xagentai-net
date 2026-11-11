# Changelog

All notable changes to **Artificial Intelligence for Burp Suite — XagentAI**
are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-11-11

Initial public release.

### Added

- **Six AI providers** out of the box:
  - Cloud: **Claude** (Anthropic Messages API), **OpenAI** (ChatGPT API),
    **NVIDIA** (NIM / API Catalog).
  - Local: **LM Studio**, **Ollama**, **llama.cpp** — all through their
    OpenAI-compatible endpoints.
- **Right-click entry** "Extensions → Artificial Intelligence for Burp Suite
  - XagentAI → Analyze with AI" on:
  Proxy History, Repeater, Intruder (editor), Scanner Issues, Target Site
  Map, WebSocket History.
- **Top-bar "XagentAI" tab** hosting a Settings panel with 9 sub-tabs:
  Active provider · Claude · OpenAI · NVIDIA · LM Studio · Ollama ·
  llama.cpp · Behaviour · About.
- **Per-provider Test connection** button that round-trips a short request
  and reports latency + outcome.
- **Result dialog** with Markdown-rendered analysis and three actions:
  - **Send to Repeater** — a second AI call converts the `TESTS TO RUN`
    section of the previous answer into real HTTP requests; each one opens
    in its own Repeater tab named `XagentAI: <test name>`. Falls back to
    sending the original request when no tests were proposed.
  - **Send to Intruder** — a second AI call picks the best `§...§`
    insertion point(s) on the original request; Intruder opens with the
    positions already set and the suggested payload list is placed on the
    clipboard (paste into Payloads → Simple list).
  - **Copy as Markdown** — raw analysis to the clipboard.
- **Sanitize PII** combo (`ACTIVE` / `INACTIVE` / `AUTO`, default `AUTO`).
  In `AUTO`, sensitive header values (`Authorization`, `Proxy-Authorization`,
  `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-Amz-Security-Token`,
  `X-CSRF-Token`) are redacted only when the active provider is cloud-hosted;
  local providers always receive the request as-is since nothing leaves the
  machine.
- **LM Studio Model combo** with a **Refresh** button that calls
  `/v1/models` and marks the currently-loaded model in bold.
- **Claude 5 compatibility**: the deprecated `temperature` parameter is
  automatically omitted for the Claude 5 family (`claude-opus-5-*`,
  `claude-sonnet-5-*`, `claude-haiku-5-*`, `claude-fable-5-*`).
- **OpenAI reasoning-model compatibility**: `temperature` is omitted for
  `o1*`, `o3*`, `o4*` and `gpt-5*` models, which do not accept it.
- **HTTP wire-format normalization** that guarantees the mandatory CRLF
  blank line between headers and body before handing a request to Repeater
  (prevents "The HTTP header block doesn't have a blank line at the end"
  when the AI forgets it).
- **Fat-JAR packaging** (Gson 2.15.0 and commonmark 0.32.0 shaded in) —
  the extension is a single self-contained JAR.
- **Developer convenience**: `installToBurp` Gradle task that copies the
  built JAR to a local `burp-plugins` folder on every build, configured
  through a gitignored `gradle.properties.local`.

### Security

- No telemetry. The plugin does not contact `xagentai.net` or any third
  party of its own; the only outbound traffic is to the AI endpoint the
  operator configured.
- API keys are stored through Burp's `PersistedObject` (extension
  preferences), never written to the plugin logs or exposed in error
  messages.

[0.1.0]: https://github.com/marcodemm/artificial-intelligence-for-burp-suite-xagentai-net/releases/tag/v0.1.0
