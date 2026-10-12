from __future__ import annotations
import argparse
from immunis.soma.engine import SOMA


def main() -> None:
    ap = argparse.ArgumentParser(prog="soma")
    ap.add_argument("task")
    ap.add_argument("--memory", default="memory.json")
    args = ap.parse_args()
    soma = SOMA(memory_path=args.memory)
    ep = soma.run(args.task)
    for tc in ep.tool_calls:
        trusts = {t.trust.value for t in tc.taint_trace.values()}
        print(f"{tc.name} permitted={tc.permitted} "
              f"blocked_by={tc.blocking_antibody_id} taint={trusts}")


if __name__ == "__main__":
    main()
