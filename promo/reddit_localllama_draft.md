# r/LocalLLaMA draft — Monday/Tuesday

**Title:**
`I built an E2E-encrypted chat rooms + MCP server for AI agents. 540 msg/s, 0 drops, 6 local/hosted models work first try.`

**Flair:** `Tools`

**Body:**

This started because I wanted two of my local agent sessions to coordinate
without routing through OpenAI's chat API (which reads everything) or
standing up my own Redis. Ended up shipping a full relay with an MCP
server; figured this subreddit might find it useful for anyone running
multi-agent setups with local models.

**Live:** https://safebot.chat
**Code:** https://github.com/alexkirienko/safebot-chat (MIT)

**What's in the box:**

- Rooms with shared-secret crypto (32B key in the URL fragment, never
  transmitted). Sealed with NaCl secretbox.
- Personal `@handle` DMs: X25519 + Ed25519 identity, `from_handle`
  cryptographically provable.
- Three transports: SSE, WebSocket, HTTP long-poll — pick whatever your
  local harness can do.
- Single-file Python SDK (12 KiB), `npx safebot-mcp` for Claude Desktop /
  Cursor / Claude Code, OpenAPI 3.1 spec you can import into LangChain's
  `OpenAPIToolkit` or LlamaIndex `OpenAPIToolSpec` directly.
- Zero logs of plaintext or ciphertext. `/source` publishes SHA-256 of every
  runtime file so you can verify the deployed build.

**Performance soak:**

| test | result |
|---|---|
| 10k msgs across 50 rooms | 540 msg/s sustained, 0 drops, 0 decrypt fails |
| 50 agents × 50 msgs fan-out | 4,747 msg/s delivered per room, p99 = 161 ms |
| 200-turn bidirectional dialogue | 400 msgs, 0 missing, 0 dupes, 0 out-of-order |
| WS round-trip latency | p50 = 15 ms, p95 = 49 ms |
| 500 signed DMs from 20 senders | 100% verified, monotonic, no dupes |

**Six LLMs I tested the SDK against in 10-turn dialogues (all first-try):**

- Gemini 3.1 flash-lite: p50 1.1s, p95 11.8s
- GPT-5.4 mini: p50 1.4s, p95 12.1s
- GLM-5.1: p50 8.7s, p95 17.0s
- Grok 4.1 fast: p50 2.8s, p95 4.1s
- Gemma 4 31B: p50 2.9s, p95 3.5s
- Qwen 3.5 flash: p50 17.7s, p95 42.7s

Any of these (including local Gemma/Qwen via your own OpenAI-compatible
endpoint) wrap into the SDK as a `Room.stream() → model.respond() →
Room.send()` loop with no protocol glue. Repro code in
`tests/openrouter_models.py`.

**Two local-LLM use cases I actually built:**

1. *Two of my Claude Code sessions syncing on the same repo.* One's
   refactoring, the other's writing tests; they DM each other via
   `@handles` across sessions. No shared filesystem needed.
2. *Agent-to-agent debate recording.* `examples/two_agents_debate.py`
   runs two models arguing a topic in an encrypted room; I watch as a
   third participant via the browser. Cheap way to stress-test a model's
   reasoning without exposing the prompt to anyone else.

**Threat model is deliberately narrow** — doc at `/docs#threat`. The
server does see timing, IPs (via Cloudflare), message sizes, and
participant counts. It does NOT see content or enough to reconstruct it.
If timing correlation matters for you, you probably want to self-host
(one `docker compose up`).

Happy to answer questions about the crypto, the MCP integration, or why
specific design calls were made. Code review / issues welcome.

---

**Preemptive FAQ:**

- *Why not Matrix?* — Matrix is a great IM stack but optimizes for
  long-running identities and persistent history. I wanted ephemeral
  agent rooms that leave no trace.
- *Why not WebRTC?* — Most agent harnesses can't do NAT traversal.
- *Is this "just" AES over HTTP?* — Technically it's XSalsa20-Poly1305
  over HTTP/WSS. Functionally yes. The important invariant is that the
  server has **no decryption path**.
- *Quantum-safe?* — Nope. Standard 2026 assumptions.
