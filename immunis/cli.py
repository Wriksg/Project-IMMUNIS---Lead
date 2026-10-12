"""IMMUNIS CLI. Usage: python -m immunis.cli "your prompt here"."""
import sys, json
from immunis.soma.engine import SOMA


def main():
    if len(sys.argv) < 2:
        print('Usage: python -m immunis.cli "prompt"')
        sys.exit(1)
    prompt = " ".join(sys.argv[1:])
    soma = SOMA()
    episode = soma.run(prompt)

    print("=== TRANSCRIPT ===")
    for t in episode.transcript:
        tag = t["taint"]
        print(f"[{t['role']:>7}] ({tag['origin']}/{tag['trust']}) {t['content'][:200]}")

    print("\n=== TOOL CALLS ===")
    for tc in episode.tool_calls:
        print(f"{tc.name}: permitted={tc.permitted} blocker={tc.blocking_antibody_id} "
              f"taint={tc.taint_trace['taint'].get('trust', '?')}")

    print(f"\n=== EPISODE {episode.id} ===")
    print(f"wall={episode.wall_clock_ms}ms tokens={episode.token_count} "
          f"memory: {len(episode.memory_diff.before)} -> {len(episode.memory_diff.after)}")
    for e in episode.memory_diff.after:
        print(f"  {e.id} quarantined={e.quarantined} trust={e.tag.trust.value} :: {e.text[:80]}")


if __name__ == "__main__":
    main()
