#!/usr/bin/env python3
"""A reference memory-system timing model, from an `axis.memsys.v1` manifest.

The second reading of the contract at the top of `src/emit/memsys_engine.c`
(`docs/memory_system_design.md` §5, MS4). It is written to be READ, not to be
fast, and it is structured differently from the engine on purpose -- a set is
a list of line records here, a slot index there -- so that the two agreeing is
evidence about the contract rather than about one shared way of coding it.

What an access costs, in core cycles: each cache level reached charges its
latency; each step down charges the round trip, 2 x hops x (hop + router
cycles); a DRAM charges its controller latency plus the row buffer's answer
in DRAM cycles (CL hit, tRCD+CL idle, tRP+tRCD+CL conflict; tRCD+CL under a
closed page), converted up through tCK and the system clock; a scratchpad its
latency. Write-backs, write-throughs, writes around a no-write-allocate cache
and prefetches are performed and counted, never charged. See the engine's
header for replacement, inclusion and prefetch -- and for coherence (MS5),
which this model also checks: after every coherent access, no line is held M
or E by one port and by anyone else at all, and no line has two O holders.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Line:
    tag: int
    dirty: bool = False
    stamp: int = 0          # LRU: last use; FIFO: fill order
    state: str = ""         # a port's coherence state: "M", "O", "E", "S"; "" outside it


@dataclass
class Stats:
    hits: int = 0
    misses: int = 0
    writebacks: int = 0
    evictions: int = 0
    prefetches: int = 0
    back_invalidations: int = 0
    row_hits: int = 0
    row_idle: int = 0
    row_conflicts: int = 0
    accesses: int = 0
    forwards: int = 0
    invalidations: int = 0
    upgrades: int = 0


class Cache:
    def __init__(self, spec: dict, index: int):
        self.spec = spec
        self.name = spec["name"]
        self.sets = spec["sets"]
        self.ways = spec["ways"]
        self.line_bytes = spec["line_bytes"]
        self.latency = spec["latency_cycles"]
        self.policy = spec["replacement"]
        self.write_back = spec["write_policy"] == "write-back"
        self.write_allocate = spec["allocate"] == "write-allocate"
        self.inclusion = spec["inclusion"]
        self.degree = spec["prefetch_degree"] if spec["prefetch"] == "next-line" else 0
        # Each set: `ways` positions, None where invalid -- position is the way.
        self.ways_of = [[None] * self.ways for _ in range(self.sets)]
        self.tree = [[0] * max(self.ways - 1, 1) for _ in range(self.sets)]
        self.rng = (0x9E3779B9 ^ index) & 0xFFFFFFFF
        self.stats = Stats()

    def lookup(self, tag: int):
        for way, line in enumerate(self.ways_of[tag % self.sets]):
            if line is not None and line.tag == tag:
                return way, line
        return None, None

    # The tree: node k's children are 2k+1 (left, the lower ways) and 2k+2.
    def _tree_touch(self, s: int, way: int):
        node, lo, hi = 0, 0, self.ways
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if way < mid:
                self.tree[s][node] = 1
                node, hi = 2 * node + 1, mid
            else:
                self.tree[s][node] = 0
                node, lo = 2 * node + 2, mid

    def _tree_victim(self, s: int) -> int:
        node, lo, hi = 0, 0, self.ways
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if self.tree[s][node]:
                node, lo = 2 * node + 2, mid
            else:
                node, hi = 2 * node + 1, mid
        return lo

    def touch(self, tag: int, way: int, clock: "Clock"):
        if self.policy == "lru":
            self.ways_of[tag % self.sets][way].stamp = clock.tick()
        elif self.policy == "plru":
            self._tree_touch(tag % self.sets, way)

    def victim_way(self, s: int) -> int:
        row = self.ways_of[s]
        for way, line in enumerate(row):
            if line is None:
                return way
        if self.policy == "plru":
            return self._tree_victim(s)
        if self.policy == "random":
            x = self.rng
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= x >> 17
            x ^= (x << 5) & 0xFFFFFFFF
            self.rng = x
            return x % self.ways
        # LRU and FIFO both take the smallest stamp; the first of equals.
        best = 0
        for way in range(1, self.ways):
            if row[way].stamp < row[best].stamp:
                best = way
        return best


class Clock:
    def __init__(self):
        self.now = 0

    def tick(self) -> int:
        self.now += 1
        return self.now


class Model:
    def __init__(self, system: dict):
        self.system = system
        ic = system["interconnect"]
        self.kind, self.cols, self.rows = ic["topology"], ic["cols"], ic["rows"]
        self.per_hop = ic["hop_cycles"] + ic["router_cycles"]
        self.clock_ps = system["clock_ps"]
        self.nodes = system["nodes"]
        self.index = {n["name"]: i for i, n in enumerate(self.nodes)}
        self.caches = {i: Cache(n, i) for i, n in enumerate(self.nodes) if n["kind"] == "cache"}
        self.endpoint_stats = {i: Stats() for i, n in enumerate(self.nodes) if n["kind"] != "cache"}
        self.open_rows = {i: {} for i, n in enumerate(self.nodes) if n["kind"] == "dram"}
        self.clock = Clock()
        self.protocol = system["coherence"]["protocol"]
        self.violations = 0

    # -- geometry ----------------------------------------------------------------
    def hops(self, a: int, b: int) -> int:
        (ax, ay), (bx, by) = (self.nodes[a]["x"], self.nodes[a]["y"]), (self.nodes[b]["x"], self.nodes[b]["y"])
        dx, dy = abs(ax - bx), abs(ay - by)
        if self.kind == "torus":
            return min(dx, self.cols - dx) + min(dy, self.rows - dy)
        if self.kind == "ring":
            return min(dx, self.cols - dx)
        if self.kind == "crossbar":
            return int((ax, ay) != (bx, by))
        return dx + dy

    def trip(self, a: int, b: int) -> int:
        return 2 * self.hops(a, b) * self.per_hop

    def below(self, i: int):
        nxt = self.nodes[i]["next"]
        return self.index[nxt] if nxt else None

    def port(self, core: str):
        for i, n in enumerate(self.nodes):
            if n["core"] == core:
                return i
        return None

    def region(self, addr: int):
        for r in self.system["address_map"]:
            if r["base"] <= addr < r["base"] + r["size"]:
                return r
        return None

    # -- endpoints ---------------------------------------------------------------
    def endpoint(self, e: int, addr: int) -> int:
        node, st = self.nodes[e], self.endpoint_stats[e]
        st.accesses += 1
        if node["kind"] != "dram":
            return node["latency_cycles"]
        d = node["dram"]
        row = addr // d["row_bytes"]
        bank, row_id = row % node["banks"], row // node["banks"]
        opened = self.open_rows[e].get(bank)
        if d["page_policy"] == "closed":
            cycles = d["trcd"] + d["tcl"]
            st.row_idle += 1
        elif opened == row_id:
            cycles = d["tcl"]
            st.row_hits += 1
        elif opened is None:
            cycles = d["trcd"] + d["tcl"]
            st.row_idle += 1
        else:
            cycles = d["trp"] + d["trcd"] + d["tcl"]
            st.row_conflicts += 1
        if d["page_policy"] != "closed":
            self.open_rows[e][bank] = row_id
        ps = cycles * d["tck_ps"]
        return node["latency_cycles"] + -(-ps // self.clock_ps)

    # -- posted writes, back-invalidation, fills ------------------------------------
    def write_below(self, i: int, tag: int, endpoint: int):
        b = self.below(i)
        if b is None:
            return
        if b not in self.caches:
            self.endpoint(endpoint if endpoint is not None else b, tag * self.caches[i].line_bytes)
            return
        cb = self.caches[b]
        way, line = cb.lookup(tag)
        if line is not None:
            if cb.write_back:
                line.dirty = True
            else:
                self.write_below(b, tag, endpoint)
            cb.touch(tag, way, self.clock)
        elif cb.write_allocate:
            self.fill(b, tag, cb.write_back, endpoint)
            if not cb.write_back:
                self.write_below(b, tag, endpoint)
        else:
            self.write_below(b, tag, endpoint)

    def above(self, i: int):
        """Every cache with `i` somewhere below it."""
        for j in self.caches:
            k = self.below(j)
            while k is not None:
                if k == i:
                    yield j
                    break
                k = self.below(k)

    def back_invalidate(self, i: int, tag: int, endpoint: int):
        for j in sorted(self.above(i)):
            cj = self.caches[j]
            way, line = cj.lookup(tag)
            if line is None:
                continue
            if line.dirty:
                cj.stats.writebacks += 1
                self.write_below(i, tag, endpoint)
            cj.ways_of[tag % cj.sets][way] = None
            self.caches[i].stats.back_invalidations += 1

    def fill(self, i: int, tag: int, dirty: bool, endpoint: int) -> int:
        c = self.caches[i]
        s = tag % c.sets
        way = c.victim_way(s)
        old = c.ways_of[s][way]
        if old is not None:
            c.stats.evictions += 1
            c.ways_of[s][way] = None
            if c.inclusion == "inclusive":
                self.back_invalidate(i, old.tag, endpoint)
            b = self.below(i)
            if b is not None and b in self.caches and self.caches[b].inclusion == "exclusive":
                cb = self.caches[b]
                bw, bl = cb.lookup(old.tag)
                if bl is None:
                    self.fill(b, old.tag, old.dirty, endpoint)
                elif old.dirty:
                    bl.dirty = True
                if old.dirty:
                    c.stats.writebacks += 1
            elif old.dirty:
                c.stats.writebacks += 1
                self.write_below(i, old.tag, endpoint)
        line = Line(tag, dirty)
        c.ways_of[s][way] = line
        if c.policy == "fifo":
            line.stamp = self.clock.tick()
        c.touch(tag, way, self.clock)
        return way

    # -- a read, level by level -------------------------------------------------------
    def serve(self, i: int, tag: int, endpoint: int, upward: bool) -> tuple[int, Line | None]:
        c = self.caches[i]
        cost = c.latency
        way, line = c.lookup(tag)
        if line is not None:
            c.stats.hits += 1
            c.touch(tag, way, self.clock)
            return cost, line
        c.stats.misses += 1
        keep = not (upward and c.inclusion == "exclusive")
        b = self.below(i)
        dirty = False
        if b is not None and b in self.caches:
            cost += self.trip(i, b)
            sub, got = self.serve(b, tag, endpoint, True)
            cost += sub
            if got is not None and self.caches[b].inclusion == "exclusive":
                dirty = got.dirty
                cb = self.caches[b]
                cb.ways_of[tag % cb.sets][cb.lookup(tag)[0]] = None
        else:
            e = endpoint if endpoint is not None else b
            cost += self.trip(i, e) + self.endpoint(e, tag * c.line_bytes)
        if not keep:
            return cost, None
        self.fill(i, tag, dirty, endpoint)
        for k in range(1, c.degree + 1):
            if c.lookup(tag + k)[1] is None:
                self.fill(i, tag + k, False, endpoint)
                c.stats.prefetches += 1
        return cost, c.lookup(tag)[1]

    # -- coherence ---------------------------------------------------------------------
    def one_way(self, a: int, b: int) -> int:
        return self.hops(a, b) * self.per_hop

    def peers(self, port: int, home: int) -> list[int]:
        """The other ports whose path passes `home`."""
        return [j for j in self.caches if j != port and self.nodes[j]["core"] and home in self.chain(j)]

    def chain(self, j: int) -> list[int]:
        out, k = [], self.below(j)
        while k is not None:
            out.append(k)
            k = self.below(k)
        return out

    def holding(self, j: int, tag: int):
        return self.caches[j].lookup(tag)

    def drop(self, j: int, tag: int):
        c = self.caches[j]
        way, line = c.lookup(tag)
        c.ways_of[tag % c.sets][way] = None
        c.stats.invalidations += 1

    def coherent(self, port: int, addr: int, is_write: bool, target: int, home: int) -> int:
        c, lat = self.caches[port], self.caches[port].latency
        tag = addr // c.line_bytes
        peers = self.peers(port, home)
        held = [(j, self.holding(j, tag)[1]) for j in peers if self.holding(j, tag)[1] is not None]
        owner = next((j for j, line in held if line.state in ("M", "O", "E")), None)
        inv_all = max((2 * self.one_way(home, j) for j, _ in held), default=0)
        inv_others = max((2 * self.one_way(home, j) for j, _ in held if j != owner), default=0)
        via = lat + self.one_way(port, home) + self.caches[home].latency
        way, mine = c.lookup(tag)
        if not is_write:
            if mine is not None:
                c.stats.hits += 1
                c.touch(tag, way, self.clock)
                return lat
            if owner is not None:
                c.stats.misses += 1
                q = self.caches[owner]
                q.stats.forwards += 1
                line = self.holding(owner, tag)[1]
                if line.state == "M" and self.protocol == "moesi":
                    line.state = "O"
                elif line.state == "M":
                    line.state, line.dirty = "S", False
                    q.stats.writebacks += 1
                    self.write_below(owner, tag, target)
                elif line.state == "E":
                    line.state = "S"
                self.fill(port, tag, False, target)
                c.lookup(tag)[1].state = "S"
                return via + self.one_way(home, owner) + q.latency + self.one_way(owner, port)
            cost = self.serve(port, tag, target, False)[0]
            got = c.lookup(tag)[1]
            if got is not None:
                got.state = "E" if not held and self.protocol in ("mesi", "moesi") else "S"
            return cost
        if mine is not None:
            c.stats.hits += 1
            c.touch(tag, way, self.clock)
            if mine.state in ("M", "E"):
                mine.state, mine.dirty = "M", True
                return lat
            c.stats.upgrades += 1
            for j, _ in held:
                self.drop(j, tag)
            mine.state, mine.dirty = "M", True
            return via + inv_all + self.one_way(home, port)
        if owner is not None:
            c.stats.misses += 1
            self.caches[owner].stats.forwards += 1
            fwd = self.one_way(home, owner) + self.caches[owner].latency + self.one_way(owner, port)
            inv = inv_others + self.one_way(home, port)
            for j, _ in held:
                self.drop(j, tag)
            self.fill(port, tag, True, target)
            c.lookup(tag)[1].state = "M"
            return via + max(fwd, inv)
        cost = self.serve(port, tag, target, False)[0] + inv_all
        for j, _ in held:
            self.drop(j, tag)
        got = c.lookup(tag)[1]
        if got is not None:
            got.state, got.dirty = "M", True
        return cost

    def check_invariant(self, home: int, tag: int):
        states = []
        for j in self.caches:
            if self.nodes[j]["core"] and home in self.chain(j):
                line = self.holding(j, tag)[1]
                if line is not None:
                    states.append(line.state)
        exclusive = sum(st in ("M", "E") for st in states)
        if (exclusive and len(states) > 1) or sum(st == "O" for st in states) > 1:
            self.violations += 1

    def access(self, port: int, addr: int, is_write: bool) -> int:
        r = self.region(addr)
        if port is None or r is None:
            return 0
        target = self.index[r["target"]]
        if r["uncached"]:
            return self.trip(port, target) + self.endpoint(target, addr)
        if self.protocol != "none" and r["home"] and self.nodes[port]["core"]:
            home = self.index[r["home"]]
            cost = self.coherent(port, addr, is_write, target, home)
            self.check_invariant(home, addr // self.caches[port].line_bytes)
            return cost
        c = self.caches[port]
        tag = addr // c.line_bytes
        if not is_write:
            return self.serve(port, tag, target, False)[0]
        way, line = c.lookup(tag)
        if line is None and not c.write_allocate:
            c.stats.misses += 1
            self.write_below(port, tag, target)
            return c.latency
        if line is None:
            cost, line = self.serve(port, tag, target, False)
        else:
            cost = c.latency
            c.stats.hits += 1
            c.touch(tag, way, self.clock)
        if c.write_back:
            line.dirty = True
        else:
            self.write_below(port, tag, target)
        return cost

    def stats(self, i: int) -> Stats:
        return self.caches[i].stats if i in self.caches else self.endpoint_stats[i]
