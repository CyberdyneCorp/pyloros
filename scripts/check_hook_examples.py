"""Run the built hook components through the worker's binary input protocol."""
import argparse
import json
from pathlib import Path
import subprocess


def check(worker, component, event, expected):
    module = component.read_bytes()
    frame = len(module).to_bytes(4, "big") + module + event.encode()
    result = subprocess.run([worker], input=frame, capture_output=True, check=True, timeout=15)
    actual = json.loads(result.stdout)
    if actual != expected:
        raise ValueError(f"{component.name} returned {actual!r}, expected {expected!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path)
    parser.add_argument("guests", type=Path)
    args = parser.parse_args()
    cases = [
        ("event_name_hook", '{"event_type":"Δ"}', "success", "Δ\n"),
        ("event_name_hook", json.dumps({"event_type": "雪" * 10_001}, ensure_ascii=False), "success", "雪" * 10_000),
        ("event_name_hook", "{}", "error", "ValueError: Expected an event_type string"),
        ("examples/silent_hook", "{}", "success", ""),
        ("examples/counter_hook", '{"n":41}', "success", "42\n"),
        ("examples/counter_hook", '{"n":' + "9" * 4299 + "}", "success", "1" + "0" * 4299 + "\n"),
        ("examples/counter_hook", "{}", "error", "KeyError: 'n'"),
    ]
    for guest, event, status, output in cases:
        check(args.worker.resolve(), args.guests / (guest + ".wasm"), event,
              {"status": status, "output": output})
    print(f"{len(cases)} component executions passed")


if __name__ == "__main__":
    main()
