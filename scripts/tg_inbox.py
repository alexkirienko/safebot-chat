"""
Poll Telegram for new messages sent by the operator to @safebot_chat_bot.
Persists the last processed update_id so we never re-read a message.

Usage:
    sudo -E python3 tg_inbox.py            # read new messages once
    sudo -E python3 tg_inbox.py --since-hours 24   # include last 24h (ignores offset)

Env:
    TELEGRAM_BOT_TOKEN   (required — set in /etc/safebot/env)
    TG_OPERATOR_CHAT_ID  optional filter; defaults to any private chat
    TG_OFFSET_FILE       defaults to /var/lib/safebot/tg_offset
"""
from __future__ import annotations
import argparse, json, os, sys, time, urllib.parse, urllib.request

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
if not TOKEN:
    # Fallback: read from /etc/safebot/env directly (script often run via sudo)
    try:
        for line in open("/etc/safebot/env"):
            if line.startswith("TELEGRAM_BOT_TOKEN="):
                TOKEN = line.split("=", 1)[1].strip()
                break
    except Exception:
        pass
if not TOKEN:
    sys.exit("TELEGRAM_BOT_TOKEN missing")

OPERATOR = os.environ.get("TG_OPERATOR_CHAT_ID")
OFFSET_FILE = os.environ.get("TG_OFFSET_FILE", "/var/lib/safebot/tg_offset")


def load_offset() -> int:
    try:
        return int(open(OFFSET_FILE).read().strip())
    except Exception:
        return 0


def save_offset(v: int) -> None:
    os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
    with open(OFFSET_FILE, "w") as f:
        f.write(str(v))


def get_updates(offset: int, timeout: int = 0) -> list:
    url = (f"https://api.telegram.org/bot{TOKEN}/getUpdates"
           f"?offset={offset}&timeout={timeout}&allowed_updates=%5B%22message%22%5D")
    try:
        with urllib.request.urlopen(url, timeout=timeout + 15) as r:
            obj = json.loads(r.read())
        if not obj.get("ok"):
            sys.stderr.write(f"telegram error: {obj}\n"); return []
        return obj.get("result", [])
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"telegram fetch failed: {e}\n"); return []


def fmt_msg(u: dict) -> str:
    m = u.get("message") or {}
    chat = m.get("chat") or {}
    frm = m.get("from") or {}
    ts = time.strftime("%H:%M:%S", time.localtime(m.get("date", 0)))
    who = frm.get("username") or frm.get("first_name") or str(frm.get("id", "?"))
    chat_id = chat.get("id")
    body = m.get("text") or m.get("caption") or "(non-text message)"
    return f"[{ts}] {who} → chat {chat_id}: {body}"


def process_batch(updates: list, cutoff: float = 0) -> int:
    """Print operator messages in batch; return the highest update_id seen."""
    max_id = 0
    for u in updates:
        uid = u.get("update_id", 0)
        if uid > max_id: max_id = uid
        m = u.get("message") or {}
        if not m: continue
        chat = m.get("chat") or {}
        if OPERATOR and str(chat.get("id")) != str(OPERATOR): continue
        if chat.get("type") != "private": continue
        if cutoff and m.get("date", 0) < cutoff: continue
        print(fmt_msg(u), flush=True)
    return max_id


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-hours", type=float, default=0,
                    help="Ignore persisted offset, replay last N hours of messages.")
    ap.add_argument("--reset", action="store_true", help="Clear stored offset and exit.")
    ap.add_argument("--watch", action="store_true",
                    help="Long-poll forever; emit one line per new operator message as it arrives.")
    args = ap.parse_args()

    if args.reset:
        try: os.unlink(OFFSET_FILE)
        except FileNotFoundError: pass
        print("offset cleared"); return

    if args.watch:
        # Prime the offset to skip old messages when first starting a watcher.
        offset = load_offset() + 1 if load_offset() else 0
        # If there's no saved offset, fast-forward past everything already
        # queued so the watcher only emits TRULY new messages.
        if offset == 0:
            pending = get_updates(0, timeout=0)
            max_id = process_batch(pending, cutoff=0)
            if max_id:
                offset = max_id + 1
                save_offset(max_id)
        while True:
            updates = get_updates(offset, timeout=55)
            if not updates:
                continue
            max_id = process_batch(updates, cutoff=0)
            if max_id:
                offset = max_id + 1
                save_offset(max_id)
        return

    # One-shot mode
    if args.since_hours > 0:
        offset = 0
        cutoff = time.time() - args.since_hours * 3600
    else:
        offset = load_offset() + 1 if load_offset() else 0
        cutoff = 0
    updates = get_updates(offset, timeout=0)
    if not updates: return
    max_id = process_batch(updates, cutoff=cutoff)
    if max_id:
        save_offset(max_id)


if __name__ == "__main__":
    main()
