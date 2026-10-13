#!/usr/bin/env python3
"""Falsification gate for the first shared specialist-unit timing increment."""
from __future__ import annotations

from collections import Counter

from shared_backend_model import SCHEMA, simulate


def workload(*, shared: bool, streams: list[list[dict]], units: int = 2,
             request_ports: int = 2, result_ports: int = 2,
             input_delay: int = 0, output_delay: int = 0,
             pipelined: bool = False) -> dict:
    return {"schema": SCHEMA,
            "config": {"contexts": len(streams), "units_total": units,
                       "request_ports_total": request_ports,
                       "result_ports_total": result_ports,
                       "queue_depth_per_pool": 16, "shared": shared,
                       "input_delay": input_delay, "output_delay": output_delay,
                       "pipelined": pipelined},
            "streams": streams}


def independent(count: int, latency: int = 3) -> list[dict]:
    return [{"name": f"u{i}", "latency": latency} for i in range(count)]


def chain(count: int, latency: int = 3) -> list[dict]:
    return [{"name": f"u{i}", "latency": latency,
             "deps": [f"u{i - 1}"] if i else []} for i in range(count)]


def check() -> None:
    # Equal total units: a busy context can use the other context's idle
    # specialist, while both saturated contexts have no phantom extra units.
    skew_private = simulate(workload(shared=False, streams=[independent(8), []]))
    skew_shared = simulate(workload(shared=True, streams=[independent(8), []]))
    assert skew_shared["cycles"] < skew_private["cycles"], (skew_private, skew_shared)
    balanced_private = simulate(workload(shared=False, streams=[independent(8), independent(8)]))
    balanced_shared = simulate(workload(shared=True, streams=[independent(8), independent(8)]))
    assert balanced_shared["unit_starts"] == balanced_private["unit_starts"] == 16
    assert balanced_shared["cycles"] >= balanced_private["cycles"], (balanced_private, balanced_shared)
    # Exposed trace makes resource conservation inspectable independently of
    # the aggregate cycle count. Both physical copies are nonpipelined here.
    trace = balanced_shared["operations"]
    assert max(Counter(o["submitted_at"] for o in trace).values()) <= 2
    assert max(Counter(o["result_granted_at"] for o in trace).values()) <= 2
    for unit in range(2):
        starts_on_unit = sorted((o for o in trace if o["unit"] == unit),
                                key=lambda o: o["started_at"])
        assert all(b["started_at"] >= a["compute_done"]
                   for a, b in zip(starts_on_unit, starts_on_unit[1:]))
    assert all(o["submitted_at"] <= o["started_at"] < o["compute_done"] <=
               o["result_granted_at"] <= o["delivered_at"]
               for o in trace)

    # A remote dependent chain must pay for both directions of transport.
    zero = simulate(workload(shared=True, streams=[chain(4), []]))
    delayed = simulate(workload(shared=True, streams=[chain(4), []],
                                input_delay=2, output_delay=2))
    assert delayed["cycles"] > zero["cycles"] + 4, (zero, delayed)

    # The unit count cannot stand in for request or result bandwidth.
    fast = simulate(workload(shared=True, streams=[independent(6, 1), independent(6, 1)],
                             units=2, request_ports=2, result_ports=2, pipelined=True))
    narrow_input = simulate(workload(shared=True, streams=[independent(6, 1), independent(6, 1)],
                                     units=2, request_ports=1, result_ports=2, pipelined=True))
    narrow_output = simulate(workload(shared=True, streams=[independent(6, 1), independent(6, 1)],
                                      units=2, request_ports=2, result_ports=1, pipelined=True))
    assert fast["cycles"] < narrow_input["cycles"] and fast["cycles"] < narrow_output["cycles"], (fast, narrow_input, narrow_output)
    assert sum(c["request_port_stall_cycles"] for c in narrow_input["per_context"]) > 0
    assert narrow_output["result_port_stall_cycles"][0] > 0

    # A saturated peer must not silence the other context under RR service.
    fair = simulate(workload(shared=True, streams=[independent(24), independent(24)],
                             units=2, request_ports=1, result_ports=1))
    assert [row["operations"] for row in fair["per_context"]] == [24, 24]
    assert max(row["max_ready_to_start"] for row in fair["per_context"]) < fair["cycles"]

    # Four physical lanes can host a two-lane vector-shaped request and
    # independent scalar work in the same beat. A full-width request claims
    # all lanes atomically and cannot overlap a scalar issue that cycle.
    mixed = simulate(workload(shared=True,
        streams=[[{"name": "v", "latency": 3, "lanes": 2}],
                 [{"name": "s0", "latency": 3}, {"name": "s1", "latency": 3}]],
        units=4, request_ports=2, result_ports=2))
    mixed_v = next(o for o in mixed["operations"] if o["name"] == "v")
    concurrent = [o for o in mixed["operations"] if o["started_at"] == mixed_v["started_at"]]
    assert len(mixed_v["units"]) == 2 and len(concurrent) >= 2, mixed
    assert len({u for o in concurrent for u in o["units"]}) == sum(len(o["units"]) for o in concurrent)
    full = simulate(workload(shared=True,
        streams=[[{"name": "v", "latency": 3, "lanes": 4, "release": 2}],
                 [{"name": f"s{i}", "latency": 2} for i in range(20)]],
        units=4, request_ports=2, result_ports=2))
    full_v = full["operations"][0]
    assert full_v["started_at"] < full["cycles"] // 2 and full_v["units"] == [0, 1, 2, 3], full
    assert all(o["name"] == "v" for o in full["operations"]
               if o["started_at"] == full_v["started_at"]), full

    # Refuse an impossible private topology and a forward dependency.
    try:
        simulate(workload(shared=False, streams=[[{"name": "a", "latency": 1}], []], units=1))
    except ValueError:
        pass
    else:
        raise AssertionError("unequal private unit split was accepted")
    try:
        simulate(workload(shared=True, streams=[[{"name": "a", "latency": 1, "deps": ["b"]},
                                               {"name": "b", "latency": 1}], []]))
    except ValueError:
        pass
    else:
        raise AssertionError("forward dependence was accepted")

    print("shared backend: 9 property groups PASS")
    print(f"skew private/shared cycles: {skew_private['cycles']}/{skew_shared['cycles']}")
    print(f"balanced private/shared cycles: {balanced_private['cycles']}/{balanced_shared['cycles']}")
    print(f"4-op chain zero/delayed cycles: {zero['cycles']}/{delayed['cycles']}")
    print(f"2-lane vector/scalar same beat: {mixed_v['started_at']}; late 4-lane vector start: {full_v['started_at']}")


if __name__ == "__main__":
    check()
