#!/usr/bin/env python3
"""A reference reading of TIMED memory-system accesses (U1).

The second reading of the TIMED ACCESSES section at the top of
`src/emit/memsys_engine.c` (`docs/unified_engine_design.md` §3). Where the
untimed model (`memsys_model.py`, whose state machinery this reuses --
replacement, fills, write-backs and inclusion are already held to the engine
by `memsys_sim_check.py`) adds up a cost level by level, this one follows a
request through ABSOLUTE time: a request arrives at a level at a cycle, and
each level says at what cycle its answer leaves. The engine keeps one running
cost from the access's start; agreeing is evidence about the contract.

  - A level answers a hit `latency` after arrival, or when the line's fill
    arrives if that is later.
  - A miss waits, after the lookup, for the MSHR that frees first (when all
    `mshrs` are busy), goes down, and the line is installed with the time
    its data is back; that MSHR is busy until then.
  - A DRAM access waits for its bank, takes the controller latency and the
    row buffer's answer, and needs its channel's bus for the last `burst`
    cycles of it; a busy bus pushes the end later. The bank is then busy
    for the row operation (tRP, tRCD -- not CL) and the burst, from the start.
  - Prefetches: next-line at a demand miss (from the miss's departure);
    with every MSHR busy, a prefetch waits for the first to free if one of
    the level's `prefetch_queue` slots is free (a slot is held until its
    prefetch starts), and is dropped otherwise;
    stride trained by a request's first line, fired for every line of a
    request; best-offset per Michaud with the listed constants. A prefetch
    is a fetch from below that takes an MSHR or is dropped.
  - Coherent regions: untimed.
"""

from __future__ import annotations

from memsys_model import Model, Stats

BOP_OFFSETS = [1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 15, 16, 18, 20, 24, 25, 27, 30, 32, 36, 40, 45, 48, 50, 54, 60, 64]
TIMED_STATS = ("fill_waits", "mshr_waits", "bank_waits", "bus_waits", "prefetch_useful", "prefetch_dropped",
               "bop_offset", "bop_rounds")


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def mix_slot(key: int, entries: int = 256) -> int:
    m = (1 << 64) - 1
    h = (key * 0x9E3779B97F4A7C15) & m
    h ^= h >> 29
    return (((h * 0xBF58476D1CE4E5B9) & m) >> 32) & (entries - 1)


def bop_slot(line: int, entries: int = 256) -> int:
    m = (1 << 64) - 1
    h = (line * 0x9E3779B97F4A7C15) & m
    return (h ^ (h >> 31)) & (entries - 1)


class TimedModel(Model):
    def __init__(self, system: dict):
        super().__init__(system)
        self.extra = {i: {k: 0 for k in TIMED_STATS} for i in range(len(self.nodes))}
        self.mshr = {i: [0] * max(n.get("mshrs", 0), 1) for i, n in enumerate(self.nodes) if n["kind"] == "cache"}
        # per cache, the cycle each waiting prefetch starts (a slot is free once it has)
        self.queue = {i: [0] * n.get("prefetch_queue", 0) for i, n in enumerate(self.nodes) if n["kind"] == "cache"}
        self.kinds = {i: set(n.get("prefetch", "").split()) for i, n in enumerate(self.nodes) if n["kind"] == "cache"}
        self.stride = {i: {} for i in self.caches}
        self.bop = {i: {"rr": {}, "score": [0] * len(BOP_OFFSETS), "test": 0, "round": 0, "offset": 1}
                    for i in self.caches}
        self.bank_free = {i: {} for i, n in enumerate(self.nodes) if n["kind"] == "dram"}
        self.bus_free = {i: {} for i, n in enumerate(self.nodes) if n["kind"] == "dram"}
        self.line_bytes = next((n["line_bytes"] for n in self.nodes if n["kind"] == "cache"), 64)
        self.start = 0
        self.key = 0
        self.first = False

    def degree(self, i: int) -> int:
        n = self.nodes[i]
        return max(n.get("prefetch_degree", 0), 1) if self.kinds[i] else 0

    def mshrs(self, i: int) -> int:
        return self.nodes[i].get("mshrs", 0)

    # -- DRAM, in absolute time ------------------------------------------------
    def endpoint_at(self, e: int, addr: int, t: int) -> int:
        node = self.nodes[e]
        if node["kind"] != "dram":
            self.endpoint(e, addr)
            return t + node["latency_cycles"]
        d = node["dram"]
        bank = (addr // d["row_bytes"]) % node["banks"]
        free = self.bank_free[e].get(bank, 0)
        if free > t:
            self.extra[e]["bank_waits"] += 1
            t = free
        start = t
        # the row buffer's answer, as the untimed reading computes it (and its counters)
        before = self.endpoint_stats[e].row_hits, self.endpoint_stats[e].row_idle, self.endpoint_stats[e].row_conflicts
        end = start + self.endpoint(e, addr)
        st = self.endpoint_stats[e]
        if d["page_policy"] == "closed" or st.row_idle > before[1]:
            row_op = d["trcd"]
        elif st.row_conflicts > before[2]:
            row_op = d["trp"] + d["trcd"]
        else:
            row_op = 0
        burst = max(ceil_div(ceil_div(self.line_bytes, 2 * d.get("bus_bytes", 8)) * d["tck_ps"], self.clock_ps), 1)
        channel = (addr // self.line_bytes) % max(d.get("channels", 1), 1)
        xfer = end - min(burst, end - start)
        busy = self.bus_free[e].get(channel, 0)
        if busy > xfer:
            self.extra[e]["bus_waits"] += 1
            end += busy - xfer
            xfer = busy
        self.bus_free[e][channel] = xfer + burst
        self.bank_free[e][bank] = start + ceil_div(row_op * d["tck_ps"], self.clock_ps) + burst
        return end

    # -- prefetching -------------------------------------------------------------
    def free_mshr(self, i: int):
        slots = self.mshr[i]
        k = min(range(len(slots)), key=lambda j: (slots[j], j))
        return k, slots[k]

    def fetch_below(self, i: int, tag: int, endpoint: int, t: int) -> tuple[int, bool]:
        """From cache i at cycle t: when `tag` is back at i, and whether it came dirty."""
        b = self.below(i)
        if b is not None and b in self.caches:
            back, got = self.serve_at(b, tag, endpoint, True, t + self.trip(i, b))
            dirty = False
            if got is not None and self.caches[b].inclusion == "exclusive":
                dirty = got.dirty
                cb = self.caches[b]
                cb.ways_of[tag % cb.sets][cb.lookup(tag)[0]] = None
            return back, dirty
        e = endpoint if endpoint is not None else b
        if e is None:
            return t, False
        return self.endpoint_at(e, tag * self.caches[i].line_bytes, t + self.trip(i, e)), False

    def prefetch(self, i: int, tag: int, endpoint: int, t: int) -> int | None:
        c = self.caches[i]
        if c.lookup(tag)[1] is not None:
            return None
        k = None
        if self.mshrs(i):
            k, free = self.free_mshr(i)
            if free > t:
                slot = next((q for q, starts in enumerate(self.queue[i]) if starts <= t), None)
                if slot is None:
                    self.extra[i]["prefetch_dropped"] += 1
                    return None
                t = free  # it waits in the queue for that MSHR
                self.queue[i][slot] = t
        # Below, the request at hand is this prefetch: it trains no stride,
        # and a best-offset level beneath judges timeliness from its start.
        key, start = self.key, self.start
        self.key, self.start = 0, t
        back, dirty = self.fetch_below(i, tag, endpoint, t)
        self.key, self.start = key, start
        self.fill(i, tag, dirty, endpoint)
        line = c.lookup(tag)[1]
        line.ready, line.pf = back, True
        if k is not None:
            self.mshr[i][k] = back
        c.stats.prefetches += 1
        return back

    def stride_train(self, i: int, tag: int, endpoint: int):
        table = self.stride[i]
        slot = mix_slot(self.key)
        e = table.get(slot)
        if self.first:
            if e is None or e["key"] != self.key:
                table[slot] = {"key": self.key, "last": tag, "stride": 0, "conf": 0}
                return
            d = tag - e["last"]
            if d and d == e["stride"]:
                e["conf"] = min(e["conf"] + 1, 3)
            else:
                e["stride"], e["conf"] = d, 0
            e["last"] = tag
        elif e is None or e["key"] != self.key:
            return
        if e["conf"] < 1 or not e["stride"]:
            return
        for k in range(1, self.degree(i) + 1):
            self.prefetch(i, tag + e["stride"] * k, endpoint, self.start)

    def bop_record(self, i: int, base: int, ready: int):
        self.bop[i]["rr"][bop_slot(base)] = (base, ready)

    def bop_trigger(self, i: int, tag: int, endpoint: int, now: int):
        b = self.bop[i]
        d = BOP_OFFSETS[b["test"]]
        if tag > d:
            hit = b["rr"].get(bop_slot(tag - d))
            if hit is not None and hit[0] == tag - d and hit[1] <= now:
                b["score"][b["test"]] += 1
        best = max(range(len(BOP_OFFSETS)), key=lambda k: (b["score"][k], -k))
        end = b["score"][best] >= 31
        b["test"] += 1
        if b["test"] == len(BOP_OFFSETS):
            b["test"] = 0
            b["round"] += 1
            end = end or b["round"] >= 100
        if end:
            b["offset"] = BOP_OFFSETS[best] if b["score"][best] > 1 else 0
            self.extra[i]["bop_offset"] = b["offset"]
            self.extra[i]["bop_rounds"] += 1
            b["score"] = [0] * len(BOP_OFFSETS)
            b["round"] = b["test"] = 0
        if not b["offset"]:
            return
        for k in range(self.degree(i)):
            pl = tag + b["offset"] + k
            back = self.prefetch(i, pl, endpoint, now)
            if back is not None:
                self.bop_record(i, pl - b["offset"], back)

    # -- a read, in absolute time ----------------------------------------------------
    def serve_at(self, i: int, tag: int, endpoint: int, upward: bool, t: int):
        c = self.caches[i]
        t += c.latency
        if "stride" in self.kinds[i] and self.key and not upward:
            self.stride_train(i, tag, endpoint)
        way, line = c.lookup(tag)
        if line is not None:
            c.stats.hits += 1
            c.touch(tag, way, self.clock)
            if getattr(line, "ready", 0) > t:
                t = line.ready
                self.extra[i]["fill_waits"] += 1
            if getattr(line, "pf", False):
                line.pf = False
                self.extra[i]["prefetch_useful"] += 1
                if "best-offset" in self.kinds[i]:
                    self.bop_trigger(i, tag, endpoint, self.start)
            return t, line
        c.stats.misses += 1
        k = None
        if self.mshrs(i):
            k, free = self.free_mshr(i)
            if free > t:
                self.extra[i]["mshr_waits"] += 1
                t = free
        leave = t
        keep = not (upward and c.inclusion == "exclusive")
        back, dirty = self.fetch_below(i, tag, endpoint, t)
        if not keep:
            return back, None
        self.fill(i, tag, dirty, endpoint)
        line = c.lookup(tag)[1]
        line.ready, line.pf = back, False
        if k is not None:
            self.mshr[i][k] = back
        if "best-offset" in self.kinds[i]:
            if not self.bop[i]["offset"]:
                self.bop_record(i, tag, back)
            self.bop_trigger(i, tag, endpoint, self.start)
        if "next-line" in self.kinds[i]:
            for k2 in range(1, self.degree(i) + 1):
                self.prefetch(i, tag + k2, endpoint, leave)
        return back, c.lookup(tag)[1]

    def access_at(self, port: int, addr: int, is_write: bool, now: int, key: int = 0, first: bool = True) -> int:
        self.start, self.key, self.first = now, key, first
        try:
            r = self.region(addr)
            if port is None or r is None:
                return now
            target = self.index[r["target"]]
            if r["uncached"]:
                return self.endpoint_at(target, addr, now + self.trip(port, target))
            if self.protocol != "none" and r["home"] and self.nodes[port]["core"]:
                return now + self.access(port, addr, is_write)
            c = self.caches[port]
            tag = addr // c.line_bytes
            if not is_write:
                return self.serve_at(port, tag, target, False, now)[0]
            way, line = c.lookup(tag)
            if line is None and not c.write_allocate:
                c.stats.misses += 1
                self.write_below(port, tag, target)
                return now + c.latency
            if line is None:
                done, line = self.serve_at(port, tag, target, False, now)
            else:
                done = now + c.latency
                c.stats.hits += 1
                c.touch(tag, way, self.clock)
                # a store is a use: stride, fill wait, first use of a prefetch
                if "stride" in self.kinds[port] and self.key:
                    self.stride_train(port, tag, target)
                    line = c.lookup(tag)[1]
                if getattr(line, "ready", 0) > done:
                    done = line.ready
                    self.extra[port]["fill_waits"] += 1
                if getattr(line, "pf", False):
                    line.pf = False
                    self.extra[port]["prefetch_useful"] += 1
                    if "best-offset" in self.kinds[port]:
                        self.bop_trigger(port, tag, target, self.start)
                    line = c.lookup(tag)[1]
            if c.write_back:
                line.dirty = True
            else:
                self.write_below(port, tag, target)
            return done
        finally:
            self.key = 0

    def timed_stats(self, i: int) -> dict:
        return dict(self.extra[i])

    def all_stats(self, i: int) -> Stats:
        return self.stats(i)
