from __future__ import annotations
import json
import time
import uuid
from typing import Any

from immunis.contracts.models import Episode, ToolCall, Trust, Origin
from immunis.soma.taint import stamp, derive, merge
from immunis.soma import tools
from immunis.soma.policy import quarantine_required
from immunis.soma.memory import MemoryStore

SYSTEM_PROMPT = ("You are SOMA, a personal assistant with memory, inbox, web, "
                 "files and messaging. Use tools to help the user.")
MAX_TOOL_TURNS = 8

TOOL_SCHEMAS: list[dict] = [
    {"name": "read_inbox", "description": "Read an inbox message by id (msg_001, msg_002).",
     "parameters": {"type": "object", "properties": {"message_id": {"type": "string"}},
                    "required": ["message_id"]}},
    {"name": "read_email", "description": "Read an email by id.",
     "parameters": {"type": "object", "properties": {"email_id": {"type": "string"}},
                    "required": ["email_id"]}},
    {"name": "fetch_page", "description": "Fetch a page by key (e.g. webpage:quarterly_report).",
     "parameters": {"type": "object", "properties": {"url": {"type": "string"}},
                    "required": ["url"]}},
    {"name": "read_file", "description": "Read a file by path.",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}},
                    "required": ["path"]}},
    {"name": "write_file", "description": "Write content to a file path.",
     "parameters": {"type": "object",
                    "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                    "required": ["path", "content"]}},
    {"name": "memory_search", "description": "Search memory.",
     "parameters": {"type": "object", "properties": {"query": {"type": "string"}},
                    "required": ["query"]}},
    {"name": "memory_write", "description": "Write a note to memory.",
     "parameters": {"type": "object", "properties": {"content": {"type": "string"}},
                    "required": ["content"]}},
    {"name": "send_message", "description": "Send a message to an address.",
     "parameters": {"type": "object",
                    "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                    "required": ["to", "body"]}},
]

_TOOL_FNS = {
    "read_inbox": tools.read_inbox,
    "read_email

> ⚠️ The response reached the length limit. Reply **continue** to get the rest.

cat > immunis/__main__.py << 'EOF'
from __future__ import annotations
import argparse, json
from immunis.soma.engine import SOMAEngine
from immunis.soma.llm import LLMClient

def main() -> None:
    p = argparse.ArgumentParser(description="SOMA assistant (immunis)")
    p.add_argument("task", nargs="?", default="Check my inbox and summarize anything important.")
    args = p.parse_args()

    engine = SOMAEngine(LLMClient())
    ep = engine.run(args.task)
    print(json.dumps({
        "episode_id": ep.id,
        "tool_calls": [{"name": t.name, "permitted": t.permitted,
                        "blocked_by": t.blocking_antibody_id} for t in ep.tool_calls],
        "memory_diff": ep.memory_diff,
        "wall_clock_ms": ep.wall_clock_ms,
    }, indent=2))

if __name__ == "__main__":
    main()
