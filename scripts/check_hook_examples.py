"""Run the built hook components through the worker's binary input protocol."""
import argparse
import json
import os
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
        ("examples/message_hook", '{"event_type":"ignored"}', "success", "ready\n"),
        ("examples/silent_hook", "{}", "success", ""),
        ("examples/counter_hook", '{"n":41}', "success", "42\n"),
        ("examples/counter_hook", '{"n":' + "9" * 4299 + "}", "success", "1" + "0" * 4299 + "\n"),
        ("examples/counter_hook", '{"n":9007199254740992}', "success", "9007199254740993\n"),
        ("examples/counter_hook", '{"n":9007199254740992.0}', "success", "9007199254740992.0\n"),
        ("examples/counter_hook", '{"n":-0.99997}', "success", "2.999999999997449e-05\n"),
        ("examples/counter_hook", '{"n":1e16}', "success", "1e+16\n"),
        ("examples/counter_hook", "{}", "error", "KeyError: 'n'"),
    ]
    wide = ",".join(f'"k{i:04d}":0' for i in range(5800))
    event = '{"n":0,"event_type":null,' + wide + r',"\u006e":41,"event_\u0074ype":"ready"}'
    cases.extend([
        ("event_name_hook", event, "success", "ready\n"),
        ("examples/counter_hook", event, "success", "42\n"),
    ])
    contexts = [
        r'{"z":true,"a":[null,"snow"],"z":false}',
        r'{"z":0,"a":{"x":1,"b":-0,"x":2},"\u007a":1e-5}',
        json.dumps({"text": "'quoted'\n\t\u200b雪"}, ensure_ascii=False),
        json.dumps({"text": "雪" * 10001}, ensure_ascii=False),
        json.dumps({str(i): i for i in range(1000)}, separators=(",", ":")),
    ]
    for values in ([1] * 3000, [n / 100 for n in range(2000)], [[[{}]]] * 900, ["a"] * 2000):
        contexts.append(json.dumps({"items": values}, separators=(",", ":")))
    contexts.extend([
        '{"v":[-0.00,0.000010,0.000100,1.23000,1.0,1.20e10,99999999999.9,9999999999999.9]}',
        json.dumps({"v": ["'", '\\', 'a"b', "雪", {"z": "a]b"}]}),
    ])
    for values in ([{"x": 1}] * 800, [{"x": i} for i in range(800)],
                   ["'"] * 2000, [f"item'{i}" for i in range(2000)],
                   ["雪" * 16] * 1000):
        contexts.append(json.dumps({"v": values}, separators=(",", ":"), ensure_ascii=False))
    contexts.extend([
        '{"v":[' + ",".join(["1e2"] * 2000) + "]}",
        '{"v":[' + ",".join(f"{i}e2" for i in range(2000)) + "]}",
        '{"v":[1,1,12,1e2,1e20,1e2,1e2,-0e2,3e-4,9e15,1.3e8]}',
        '{"v":[{"x":1,"x":2},{"x":1,"x":2},{"x":3}]}',
    ])
    for event in contexts:
        expected = (repr(json.loads(event)) + "\n")[:10_000]
        cases.append(("examples/context_hook", event, "success", expected))
    for guest, event, status, output in cases:
        check(args.worker.resolve(), args.guests / (guest + ".wasm"), event,
              {"status": status, "output": output})
    # Exercise the character limit in the worker with its normal execution budget.
    message = "🌐" * 10_001
    component = args.guests / "examples/message_hook.wasm"
    build = ["cargo", "component", "build", "--locked", "--release", "--example", "message_hook",
             "--target", "wasm32-unknown-unknown", "--target-dir", args.guests.parents[1],
             "--manifest-path", "examples/event-name-hook/Cargo.toml"]
    try:
        subprocess.run(build, env={**os.environ, "PYLOROS_HOOK_MESSAGE": message}, check=True)
        check(args.worker.resolve(), component, "{}", {"status": "success", "output": message[:10_000]})
    finally:
        subprocess.run(build, env={**os.environ, "PYLOROS_HOOK_MESSAGE": "ready"}, check=True)
    print(f"{len(cases) + 1} component executions passed")


if __name__ == "__main__":
    main()
