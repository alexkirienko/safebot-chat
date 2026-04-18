"""
Two AI agents debate each other through an end-to-end encrypted SafeBot.Chat
room. Neither the relay server nor anybody else sees the topic or the
transcript — plaintext and keys never leave this process.

Usage (once you have an OpenRouter API key):
    export OPENROUTER_API_KEY=sk-or-...
    pip install pynacl requests sseclient-py
    python two_agents_debate.py "Rust vs Go for systems programming" --turns 6

What you'll see: a live stream of two models (default: GPT and Grok)
disagreeing with each other inside the same encrypted room, taking
strict turns. The script also prints the room's URL — paste it in a
browser and you can jump in as a third participant (your messages get
the same crypto treatment automatically).

Every message is sealed client-side with NaCl secretbox (XSalsa20-
Poly1305). The 256-bit room key is generated here and never transmitted
— it lives only in the URL fragment (`#k=...`) which browsers never
send to the server.
"""
from __future__ import annotations
import argparse, base64, os, secrets, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sdk"))
import requests  # noqa: E402
import nacl.utils as _utils  # noqa: E402
from safebot import Room  # noqa: E402

BASE = os.environ.get("BASE", "https://safebot.chat")
OR_KEY = os.environ.get("OPENROUTER_API_KEY")
if not OR_KEY:
    sys.exit("Set OPENROUTER_API_KEY (get one at https://openrouter.ai/keys).")


def mint_room_url() -> str:
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    rid = "".join(secrets.choice(alpha) for _ in range(10))
    key_b64u = base64.urlsafe_b64encode(_utils.random(32)).rstrip(b"=").decode()
    return f"{BASE}/room/{rid}#k={key_b64u}"


def ask(model: str, history: list[dict]) -> str:
    r = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {OR_KEY}",
                 "HTTP-Referer": "https://safebot.chat",
                 "X-Title": "SafeBot.Chat two-agent debate",
                 "Content-Type": "application/json"},
        json={"model": model, "messages": history,
              "max_tokens": 220, "temperature": 0.5},
        timeout=90,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


def run_agent(label: str, model: str, room_url: str, topic: str,
              stance: str, opponent_label: str,
              lock: threading.Lock, state: dict, total_turns: int) -> None:
    room = Room(room_url, name=label)
    history = [{
        "role": "system",
        "content": (
            f"You are {label}, debating {opponent_label} about: {topic!r}. "
            f"Your stance: {stance}. Reply ≤ 60 words, plain text, no preamble. "
            "Be specific, technical, punchy. React to the opponent's last point. "
            "Never concede — it's a debate. If this is the first turn, open "
            "by stating your stance in one line."
        ),
    }]

    # Opener for the assigned opening agent.
    if state["whose_turn"] == label:
        opener = ask(model, history)
        history.append({"role": "assistant", "content": opener})
        room.send(opener)
        with lock:
            state["turns"] += 1
            state["whose_turn"] = opponent_label

    for msg in room.stream(include_self=False, auto_reconnect=False):
        if not msg.text or msg.sender != opponent_label:
            continue
        with lock:
            if state["turns"] >= total_turns:
                return
            if state["whose_turn"] != label:
                continue
        history.append({"role": "user", "content": msg.text})
        try:
            reply = ask(model, history)
        except Exception as e:  # noqa: BLE001
            reply = f"(model error: {e!s:.120})"
        history.append({"role": "assistant", "content": reply})
        room.send(reply)
        with lock:
            state["turns"] += 1
            state["whose_turn"] = opponent_label
            if state["turns"] >= total_turns:
                return


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("topic", help='Debate topic, e.g. "Rust vs Go"')
    ap.add_argument("--turns", type=int, default=6,
                    help="Total combined turns across both agents (default 6).")
    ap.add_argument("--model-a", default="openai/gpt-5.4-mini")
    ap.add_argument("--model-b", default="x-ai/grok-4.1-fast")
    ap.add_argument("--stance-a", default="argue FOR the first option")
    ap.add_argument("--stance-b", default="argue AGAINST the first option")
    args = ap.parse_args()

    url = mint_room_url()
    print(f"room (jump in as a third participant): {url}\n")

    state = {"turns": 0, "whose_turn": "gpt"}
    lock = threading.Lock()
    t_a = threading.Thread(target=run_agent, daemon=True,
        args=("gpt", args.model_a, url, args.topic, args.stance_a, "grok", lock, state, args.turns))
    t_b = threading.Thread(target=run_agent, daemon=True,
        args=("grok", args.model_b, url, args.topic, args.stance_b, "gpt", lock, state, args.turns))

    # Read-only watcher prints the decrypted debate as it unfolds.
    watcher = Room(url, name="human-watcher")
    w_stop = threading.Event()
    def watch():
        try:
            for m in watcher.stream(include_self=False, auto_reconnect=False):
                if w_stop.is_set(): return
                if m.text:
                    print(f"[{time.strftime('%H:%M:%S')}] {m.sender}: {m.text}\n")
        except Exception: pass
    threading.Thread(target=watch, daemon=True).start()

    t_a.start(); time.sleep(0.5); t_b.start()
    start = time.time()
    while time.time() - start < 8 * 60:
        with lock:
            if state["turns"] >= args.turns: break
        time.sleep(0.5)
    time.sleep(3)  # let last message echo out
    w_stop.set()
    print(f"\nDone. {state['turns']} turns in {time.time()-start:.1f}s.")


if __name__ == "__main__":
    main()
