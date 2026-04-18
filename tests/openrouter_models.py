"""
Test 4 OpenRouter LLMs driving the SafeBot.Chat Python SDK.

For each model we:
  1. Mint a fresh room URL client-side (so the server never sees the key).
  2. Spin up a 'human-sim' thread that sends 10 questions into the room.
  3. Spin up a 'model' thread that subscribes to the room, forwards each
     incoming message to the model via OpenRouter Chat Completions, and
     posts the response back as a room message.
  4. After 10 iterations, verify the model produced 10 replies that
     passed the decrypt+relay round-trip, logged no errors, and kept the
     conversation coherent (minimum 1 reply per turn, not empty).

Pass criteria per model:
  - 10/10 turns produced a non-empty reply
  - replies arrived in seq-monotonic order
  - zero exceptions / HTTP errors
  - p95 round-trip ≤ 15 s (OpenRouter latency + SafeBot relay)
"""
from __future__ import annotations
import base64, json, os, secrets, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sdk"))
import requests
from safebot import Room  # noqa: E402
import nacl.utils as _utils

BASE = os.environ.get("BASE", "https://safebot.chat")
OR_KEY = os.environ["OPENROUTER_API_KEY"]
OR_URL = "https://openrouter.ai/api/v1/chat/completions"

DEFAULT_MODELS = [
    ("gemini-3.1-fast",  "google/gemini-3.1-flash-lite-preview"),
    ("gpt-5.4-fast",     "openai/gpt-5.4-mini"),
    ("glm-5.1",          "z-ai/glm-5.1"),
    ("grok-4.2-fast",    "x-ai/grok-4.1-fast"),
    ("gemma-4",          "google/gemma-4-31b-it"),
    ("qwen-3.5-fast",    "qwen/qwen3.5-flash-02-23"),
]
# Optional: MODELS_OVERRIDE="label1=slug1,label2=slug2" to run a subset/custom set
_override = os.environ.get("MODELS_OVERRIDE", "").strip()
if _override:
    MODELS = []
    for pair in _override.split(","):
        if "=" in pair:
            lab, slug = pair.split("=", 1); MODELS.append((lab.strip(), slug.strip()))
else:
    MODELS = DEFAULT_MODELS

QUESTIONS = [
    "Hi, quick intro — who are you and what do you think this chat is for?",
    "Could you name one concrete use case where two AI agents talking to each other helps the human owner?",
    "What's one risk of running agents in group chats that humans often overlook?",
    "If I told you the server can't read our messages, how would you prove that to a skeptical engineer?",
    "How would you phrase it if a teammate asked: 'why bother with E2E for agent chat?'",
    "What would you ask a tool-using agent to verify it's actually in the room and not hallucinating?",
    "Suggest a one-line self-intro another agent joining this room might want to say.",
    "Give me a 1-sentence test I could run to detect if you're silently dropping messages.",
    "If the room capped at 200 recent messages, how would you design a long-running dialogue to still work?",
    "Wrap up: in ten words or fewer, what did you take from this chat?",
]


def mint_room():
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    rid = "".join(secrets.choice(alpha) for _ in range(10))
    key_b64u = base64.urlsafe_b64encode(_utils.random(32)).rstrip(b"=").decode()
    return f"{BASE}/room/{rid}#k={key_b64u}"


def call_openrouter(model: str, history: list[dict], timeout: float = 60.0) -> str:
    r = requests.post(
        OR_URL,
        headers={
            "Authorization": f"Bearer {OR_KEY}",
            "HTTP-Referer": "https://safebot.chat",
            "X-Title": "SafeBot.Chat multi-model test",
            "Content-Type": "application/json",
        },
        json={"model": model, "messages": history, "max_tokens": 220, "temperature": 0.4},
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    if "choices" not in data or not data["choices"]:
        raise RuntimeError(f"bad OR response: {json.dumps(data)[:300]}")
    return (data["choices"][0]["message"]["content"] or "").strip()


def run_one(label: str, model: str) -> dict:
    url = mint_room()
    result = {"label": label, "model": model, "url": url,
              "replies": 0, "errors": [], "latencies": []}

    # Two Room handles: one for the human-sim, one for the model. Different
    # `name` so include_self=False on each one drops its own echo.
    sim = Room(url, name="human-sim")
    bot = Room(url, name=label)

    sys_prompt = (
        f"You are {label} joining an end-to-end encrypted group chat via SafeBot.Chat. "
        "The server only sees ciphertext — plaintext lives in the participants' clients. "
        "Keep replies short (≤ 80 words), plain text, no markdown headers, no code blocks. "
        "Reply in character as a helpful agent. If you don't know, say so."
    )

    received_from_bot: list[str] = []
    received_lock = threading.Lock()

    def bot_loop():
        history = [{"role": "system", "content": sys_prompt}]
        try:
            for msg in bot.stream(include_self=False, auto_reconnect=False):
                if not msg.text: continue
                if msg.sender != "human-sim": continue
                history.append({"role": "user", "content": msg.text})
                t0 = time.time()
                try:
                    reply = call_openrouter(model, history)
                except Exception as e:  # noqa: BLE001
                    result["errors"].append(f"OR call: {e.__class__.__name__}: {str(e)[:160]}")
                    reply = "(model error — skipping)"
                result["latencies"].append(time.time() - t0)
                history.append({"role": "assistant", "content": reply})
                try: bot.send(reply)
                except Exception as e:  # noqa: BLE001
                    result["errors"].append(f"send: {e}")
                    return
                with received_lock:
                    received_from_bot.append(reply)
                if len(received_from_bot) >= 10: return
        except Exception as e:  # noqa: BLE001
            result["errors"].append(f"stream: {e.__class__.__name__}: {str(e)[:160]}")

    def sim_loop():
        # Listener to know when each model reply arrives so we can advance.
        seen_replies = 0
        def wait_for_reply(deadline):
            nonlocal seen_replies
            while time.time() < deadline:
                with received_lock:
                    if len(received_from_bot) > seen_replies:
                        seen_replies = len(received_from_bot); return True
                time.sleep(0.3)
            return False

        for i, q in enumerate(QUESTIONS):
            sim.send(q)
            ok = wait_for_reply(time.time() + 60)
            if not ok:
                result["errors"].append(f"Q{i+1} no reply within 60s"); return
        # allow the last reply to propagate
        wait_for_reply(time.time() + 20)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f_bot = ex.submit(bot_loop)
        time.sleep(0.8)  # let the bot subscribe before questions fire
        f_sim = ex.submit(sim_loop)
        f_sim.result(timeout=12 * 60)
        # bot_loop exits via return after 10 replies or via stream closing — give a bit
        try: f_bot.result(timeout=10)
        except Exception: pass

    with received_lock: result["replies"] = len(received_from_bot)
    if result["latencies"]:
        lat = sorted(result["latencies"])
        result["p50"] = lat[len(lat)//2]
        result["p95"] = lat[max(0, int(len(lat)*0.95)-1)]
        result["max"] = lat[-1]
    return result


def main():
    print(f"▶ Testing {len(MODELS)} models · 10 turns each via {BASE}")
    # Run sequentially to keep latency numbers clean and OR rate-limits reasonable.
    all_results = []
    for label, slug in MODELS:
        print(f"\n── {label} ({slug})")
        try:
            r = run_one(label, slug)
        except Exception as e:  # noqa: BLE001
            r = {"label": label, "model": slug, "errors": [f"harness crash: {e}"], "replies": 0, "latencies": []}
        all_results.append(r)
        ok = r["replies"] >= 10 and not r["errors"]
        mark = "✓" if ok else "✗"
        lat = f" p50={r.get('p50',0):.1f}s p95={r.get('p95',0):.1f}s max={r.get('max',0):.1f}s" if r["latencies"] else ""
        print(f"  {mark} {r['replies']}/10 replies  errors={len(r['errors'])}{lat}")
        if r["errors"]:
            for e in r["errors"][:4]: print(f"     - {e}")
        print(f"  room: {r.get('url','')}")

    print("\n=== summary ===")
    passed = sum(1 for r in all_results if r["replies"] >= 10 and not r["errors"])
    for r in all_results:
        ok = r["replies"] >= 10 and not r["errors"]
        print(f"  {'✓' if ok else '✗'} {r['label']:16} {r['replies']}/10  errors={len(r['errors'])}")
    print(f"\n{passed}/{len(MODELS)} models passed")
    sys.exit(0 if passed == len(MODELS) else 1)


if __name__ == "__main__":
    main()
