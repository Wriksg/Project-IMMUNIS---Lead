"""SOMA's five skills. Sandboxed, fixtured, every result taint-stamped."""
import os
from immunis.contracts.models import TaintTag, Trust, Origin
from mocks.fixtures import FIXTURES

WORKSPACE = os.getenv("IMMUNIS_WS", "sandbox_workspace")


class ToolResult:
    def __init__(self, name: str, args: dict, output: str, taint: TaintTag):
        self.name, self.args, self.output, self.taint = name, args, output, taint


def read_inbox(message_id: str) -> ToolResult:
    body = FIXTURES.get(f"inbox:{message_id}", "")
    # Content INSIDE an email is untrusted (fact of response is semi-trusted; content is not)
    return ToolResult("read_inbox", {"message_id": message_id}, body,
                      stamp_untrusted(f"inbox:{message_id}"))


def fetch_webpage(url: str) -> ToolResult:
    body = FIXTURES.get(url, "")
    return ToolResult("fetch_webpage", {"url": url}, body, stamp_untrusted(url))


def read_file(path: str) -> ToolResult:
    if ".." in path or path.startswith("/"):
        path = os.path.basename(path)
    safe = os.path.join(WORKSPACE, os.path.basename(path))  # no traversal
    body = open(safe).read() if os.path.exists(safe) else ""
    return ToolResult("read_file", {"path": path}, body, stamp_untrusted(path))


def write_file(path: str, content: str, taint: TaintTag) -> ToolResult:
    safe = os.path.join(WORKSPACE, os.path.basename(path))
    os.makedirs(WORKSPACE, exist_ok=True)
    open(safe, "w").write(content)
    return ToolResult("write_file", {"path": path, "taint": taint.trust}, "ok", taint)


def send_message(to: str, body: str, taint: TaintTag) -> ToolResult:
    """PRIVILEGED outbound action. Logs, does not really send (sandbox)."""
    return ToolResult("send_message", {"to": to, "taint": taint.trust},
                      f"[sandbox] queued to {to}", taint)


def stamp_untrusted(source_id: str) -> TaintTag:
    return TaintTag(origin=Origin.fetched_content, trust=Trust.untrusted,
                    source_id=source_id, parents=[])