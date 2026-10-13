#!/usr/bin/env python3
"""AXIS research timing model: two or more contexts contending for one unit class.

Input is axis.shared-backend.v1 JSON. Operations are timing records, not ISA
semantics; the generated AXIS executor remains the functional oracle. No
frontend, ROB, LSQ, vector semantics, clock, area, or power is modeled here.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

SCHEMA = "axis.shared-backend.v1"


@dataclass(frozen=True)
class Config:
    contexts: int
    units_total: int
    request_ports_total: int
    result_ports_total: int
    queue_depth_per_pool: int
    shared: bool
    input_delay: int = 0
    output_delay: int = 0
    pipelined: bool = False
    max_cycles: int = 100000

    @classmethod
    def parse(cls, raw: dict) -> "Config":
        allowed = set(cls.__dataclass_fields__)
        if set(raw) - allowed:
            raise ValueError(f"unknown config fields: {sorted(set(raw) - allowed)}")
        cfg = cls(**raw)
        if cfg.contexts < 1 or cfg.units_total < 1 or cfg.request_ports_total < 1 or cfg.result_ports_total < 1:
            raise ValueError("contexts, units, request ports, and result ports must be positive")
        if cfg.queue_depth_per_pool < 1 or cfg.input_delay < 0 or cfg.output_delay < 0 or cfg.max_cycles < 1:
            raise ValueError("queue depth and max cycles must be positive; delays cannot be negative")
        if not cfg.shared:
            for value in (cfg.units_total, cfg.request_ports_total, cfg.result_ports_total):
                if value % cfg.contexts:
                    raise ValueError("private resources must divide evenly among contexts")
        return cfg


@dataclass(frozen=True)
class Operation:
    context: int
    name: str
    latency: int
    deps: tuple[str, ...]
    release: int
    lanes: int


@dataclass
class State:
    op: Operation
    index: int
    status: str = "pending"
    ready_at: int | None = None
    submitted_at: int | None = None
    arrival: int | None = None
    started_at: int | None = None
    compute_done: int | None = None
    result_granted_at: int | None = None
    delivered_at: int | None = None
    pool: int | None = None
    unit: int | None = None
    units: tuple[int, ...] = ()


def parse_workload(raw: dict) -> tuple[Config, list[State]]:
    if raw.get("schema") != SCHEMA:
        raise ValueError(f"expected schema {SCHEMA}")
    cfg = Config.parse(raw["config"])
    streams = raw["streams"]
    if not isinstance(streams, list) or len(streams) != cfg.contexts:
        raise ValueError("one operation stream is required per context")
    states: list[State] = []
    for context, stream in enumerate(streams):
        if not isinstance(stream, list):
            raise ValueError("each stream must be a list")
        seen: set[str] = set()
        for row in stream:
            name = row["name"]
            deps = tuple(row.get("deps", ()))
            latency = row["latency"]
            release = row.get("release", 0)
            lanes = row.get("lanes", 1)
            if not isinstance(name, str) or not name or name in seen:
                raise ValueError(f"context {context}: operation names must be unique nonempty strings")
            if not isinstance(latency, int) or latency < 1 or not isinstance(release, int) or release < 0:
                raise ValueError(f"context {context}/{name}: latency must be positive and release nonnegative")
            max_lanes = cfg.units_total if cfg.shared else cfg.units_total // cfg.contexts
            if not isinstance(lanes, int) or lanes < 1 or lanes > max_lanes:
                raise ValueError(f"context {context}/{name}: lanes must be 1..{max_lanes}")
            if len(set(deps)) != len(deps) or any(dep not in seen for dep in deps):
                raise ValueError(f"context {context}/{name}: dependencies must name distinct earlier operations")
            states.append(State(Operation(context, name, latency, deps, release, lanes), len(states)))
            seen.add(name)
    return cfg, states


def simulate(raw: dict) -> dict:
    cfg, states = parse_workload(raw)
    pools = 1 if cfg.shared else cfg.contexts
    units_per_pool = cfg.units_total // pools
    req_ports = cfg.request_ports_total // pools
    result_ports = cfg.result_ports_total // pools
    unit_next = [[0] * units_per_pool for _ in range(pools)]
    request_rr = [0] * pools
    issue_rr = [0] * pools
    by_name = {(s.op.context, s.op.name): s for s in states}
    request_stalls = [0] * cfg.contexts
    queue_stalls = [0] * cfg.contexts
    result_stalls = [0] * pools
    starts = [0] * cfg.contexts
    max_ready_wait = [0] * cfg.contexts

    if not states:
        return {"schema": "axis.shared-backend-result.v1", "cycles": 0,
                "per_context": [], "unit_starts": 0}

    for cycle in range(cfg.max_cycles):
        # Delivery is the only event that satisfies a dependent operation.
        for s in states:
            if s.status == "outbound" and s.delivered_at <= cycle:
                s.status = "delivered"
        if all(s.status == "delivered" for s in states):
            break

        for s in states:
            if s.status == "running" and s.compute_done <= cycle:
                s.status = "computed"

        # A finite return path is distinct from execution capacity.
        for pool in range(pools):
            candidates = [s for s in states if s.status == "computed" and
                          (0 if cfg.shared else s.op.context) == pool]
            candidates.sort(key=lambda s: (s.compute_done, s.index))
            result_stalls[pool] += max(0, len(candidates) - result_ports)
            for s in candidates[:result_ports]:
                s.status = "outbound"
                s.result_granted_at = cycle
                s.delivered_at = cycle + cfg.output_delay

        # Source streams are available at release; dependency readiness waits
        # for delivered results, including the charged return route.
        for s in states:
            if s.status != "pending" or cycle < s.op.release:
                continue
            deps = [by_name[(s.op.context, d)] for d in s.op.deps]
            if all(d.status == "delivered" for d in deps):
                s.ready_at = max([s.op.release, *(d.delivered_at for d in deps)])

        for pool in range(pools):
            members = range(cfg.contexts) if cfg.shared else (pool,)
            submitted = 0
            queued = sum(s.status == "inbound" and
                         (0 if cfg.shared else s.op.context) == pool for s in states)
            # One request per context per cycle. Admission rotates its first
            # context to avoid a fixed low-index winner at a narrow port.
            order = list(members)
            if cfg.shared:
                order = order[request_rr[pool]:] + order[:request_rr[pool]]
            last_submitted = None
            for context in order:
                ready = next((s for s in states if s.op.context == context and
                              s.status == "pending" and s.ready_at is not None), None)
                if ready is None:
                    continue
                if submitted >= req_ports:
                    request_stalls[context] += 1
                    continue
                if queued >= cfg.queue_depth_per_pool:
                    queue_stalls[context] += 1
                    continue
                ready.status = "inbound"
                ready.submitted_at = cycle
                ready.arrival = cycle + cfg.input_delay
                submitted += 1
                queued += 1
                last_submitted = context
            if cfg.shared and last_submitted is not None:
                request_rr[pool] = (last_submitted + 1) % cfg.contexts

        for pool in range(pools):
            # A request of width N atomically reserves N adjacent physical
            # lanes. A blocked group holds its queue position for this beat;
            # this conservative rule prevents an endless scalar stream from
            # fragmenting the tile and starving a waiting vector operation.
            while True:
                free = [u for u in range(units_per_pool)
                        if unit_next[pool][u] <= cycle]
                if not free:
                    break
                candidates = [s for s in states if s.status == "inbound" and
                              s.arrival <= cycle and
                              (0 if cfg.shared else s.op.context) == pool]
                if not candidates:
                    break
                if cfg.shared:
                    candidates.sort(key=lambda s: ((s.op.context - issue_rr[pool]) % cfg.contexts,
                                                   s.submitted_at, s.index))
                else:
                    candidates.sort(key=lambda s: (s.submitted_at, s.index))
                s = candidates[0]
                allocation = next((tuple(range(first, first + s.op.lanes))
                                   for first in range(units_per_pool - s.op.lanes + 1)
                                   if all(unit_next[pool][u] <= cycle
                                          for u in range(first, first + s.op.lanes))), None)
                if allocation is None:
                    break
                s.status = "running"
                s.started_at = cycle
                s.pool = pool
                s.unit = allocation[0]
                s.units = allocation
                s.compute_done = cycle + s.op.latency
                for unit in allocation:
                    unit_next[pool][unit] = cycle + (1 if cfg.pipelined else s.op.latency)
                starts[s.op.context] += 1
                max_ready_wait[s.op.context] = max(max_ready_wait[s.op.context],
                                                   cycle - s.ready_at)
                if cfg.shared:
                    issue_rr[pool] = (s.op.context + 1) % cfg.contexts
    else:
        raise ValueError(f"model did not drain by max_cycles={cfg.max_cycles}")

    return {
        "schema": "axis.shared-backend-result.v1",
        "evidence": "MODELED: operation-stream resource timing, not AXIS ISA execution or RTL",
        "cycles": cycle,
        "per_context": [{"context": context,
                         "operations": starts[context],
                         "last_delivery": max((s.delivered_at for s in states
                                               if s.op.context == context), default=0),
                         "max_ready_to_start": max_ready_wait[context],
                         "request_port_stall_cycles": request_stalls[context],
                         "queue_full_stall_cycles": queue_stalls[context]}
                        for context in range(cfg.contexts)],
        "unit_starts": sum(starts),
        "result_port_stall_cycles": result_stalls,
        "operations": [{"context": s.op.context, "name": s.op.name,
                        "ready_at": s.ready_at, "submitted_at": s.submitted_at,
                        "pool": s.pool, "unit": s.unit, "units": list(s.units),
                        "lanes": s.op.lanes, "started_at": s.started_at,
                        "compute_done": s.compute_done,
                        "result_granted_at": s.result_granted_at,
                        "delivered_at": s.delivered_at} for s in states],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workload", type=Path, help="axis.shared-backend.v1 JSON")
    args = parser.parse_args()
    print(json.dumps(simulate(json.loads(args.workload.read_text())), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
