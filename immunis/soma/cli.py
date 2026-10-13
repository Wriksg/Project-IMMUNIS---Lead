from __future__ import annotations
import argparse
from immunis.soma.engine import SOMA
from immunis.soma.llm import LLMClient


def main() -> None:
    ap = argparse.ArgumentParser(prog="soma")
    ap.add_argument("task")
    ap.add_argument("--memory", default="memory.json")
    args = ap.parse_args()
    soma = SOMA(memory_path=args.memory, llm=LLMClient("soma"))
    ep = soma.run(args.task)
    print("=== ANSWER ===")
    print(ep.content)
    print("=== TOOL CALLS ===")
    for tc in ep.tool_calls:
        trusts = {t.trust.value for t in tc.taint_trace.values()}
        print(f"{tc.name} permitted={tc.permitted} "
              f"blocked_by={tc.blocking_antibody_id} taint={trusts}")
        print(f"  args={tc.arguments}")
    print(f"=== tokens={ep.token_count} wall_ms={ep.wall_clock_ms} ===")
    print("=== MEMORY DIFF ===")
    print("before:", [e.id for e in ep.memory_diff.before])
    print("after: ", [e.id for e in ep.memory_diff.after])


if __name__ == "__main__":
    main()
