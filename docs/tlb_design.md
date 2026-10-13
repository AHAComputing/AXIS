# Translation buffers, and prefetchers a host brings

Status: **TLB1, TLB2 and PF1 implemented** (a core's data, fetch and
second-level TLBs; a walker, a page table that is read, a walk cache and large
pages -- §2a; a prefetcher the library has not got, bound by a host as
predictors are; pack ABI 9). Companion to `docs/pack_simulator.md`, the overview
of the simulator these belong to, and to `docs/unified_engine_design.md`,
whose memory system already has next-line, stride and best-offset prefetchers
with bounded misses in flight.

## 1. What was missing

A program that walks a large array pays for every page it enters, and a
machine that remembers sixty-four pages pays differently from one that
remembers two thousand. The simulator charged nothing: translation was free,
so a workload's footprint showed only in its cache misses.

Prefetchers were less missing than the first reading of this suggested. A
described memory system prefetches, timed, through the same miss buffers as
a demand miss. What it cannot do is run a prefetcher this library does not
contain — the policy a study is usually about.

## 2. TLB1 — a machine remembers only so many pages

```lisp
(defcore xpages
  ...
  (tlb (data (entries 16) (ways 4)) (fetch (entries 8))
       (second (entries 64) (ways 4) (latency 3))
       (page-bytes 4096) (walk-cycles 20)))
```

* `(data ...)` is looked up by every load and store; `(fetch ...)` by fetch,
  once for each page it enters. Either may be absent.
* `(second ...)` is one table behind both. A page the first level has
  forgotten and the second holds costs the second's `latency`.
* A page nothing holds costs `walk-cycles` on top. Every level the page was
  missing from holds it afterwards; each evicts its least recently used.
* `(ways N)` makes a level set-associative; absent, any page may sit in any
  entry. `(page-bytes N)` defaults to 4096.

⚠️ **Timing, not translation.** Addresses stay what the program computes. No
page table is read, nothing faults, and there is one page size and one
address space. What is modelled is how many distinct pages a program touches
against how many the machine remembers, and what forgetting one costs.

It is a clause on the core, not a `defmemory`, for the reason a BTB is: it is
a property of one machine, has no bytes a program can address, and nothing
else in a description refers to it.

A first-level hit costs nothing beyond the instruction. That is deliberate
and validated: the instruction's declared latency already covers it, as it
covers a first-level cache hit, and a second place to write the number would
be a field nothing has to agree with. Only `(second ...)` takes a latency.

### Where a lookup happens

| Access | Trace-driven | Execution-driven |
|---|---|---|
| load | at its step; the cost is its latency | when it executes; the cost is its latency |
| store | at its step | when it **executes** — its data reaches the cache at commit, its address was translated long before |
| fetch | at each page entered; holds that fetch | the same; holds fetch until the walk is done |
| wrong path | lines fetched and accesses made down it are looked up | the pipeline's own speculation looks up as it goes |

Translation comes before the cache: on a core with timed memory the access
is put to the memory system at the cycle the walk ends.

### What is counted

`dtlb_misses`, `itlb_misses` and `page_walks` on the pack — first-level
misses of each table, and how many of either reached a walk. They are the
program's own, as the cache counters are: a lookup made by an instruction
that is squashed changes what the TLB holds and is not counted. That is how a
wrong path shows: the page a squashed load asked for is there when the
program's own load needs it, which then neither misses nor waits.

### What holds it: `tlb_check.py`

Machines identical but for their TLB, on both engines, at two lengths, each
compared with the machine translation is free on. Every figure is exact.

| Program | Machine | Misses | Walks | Extra cycles |
|---|---|---|---|---|
| chase round 6 pages | 8 entries | 6 | 6 | 6 walks, however long the chase |
| chase round 6 pages | 4 entries | every load | every load | a walk a load |
| 3 pages in one set | 8 entries, 2 ways | every load | every load | a walk a load |
| 3 pages in three sets | 8 entries, 2 ways | 3 | 3 | 3 walks |
| 3 pages eight apart | 8 entries, any way | 3 | 3 | 3 walks |
| one hot page between cold ones | 4 entries | the hot page and each cold one, once | the same | a walk each |
| chase round 6 pages | 4 entries, second level of 16 | every load | 6 | 6 walks, and the second level's latency on every load |
| 4 pages of code | fetch, 2 entries | 4 | 4 | 4 walks |
| loop over 3 pages of code | fetch, 4 entries | 3 | 3 | 3 walks |
| loop over 3 pages of code | fetch, 2 entries | 3 a trip | 3 a trip | 3 walks a trip |
| a store to a fresh page a trip | 8 entries, and 1 | one a store | one a store | at least a walk |
| a load of the code's own page | data and fetch | 1 and 1 | 2 | 2 walks |
| a load behind a mispredicted branch, then the program's own | 8 entries | 0 execution-driven, 1 trace-driven | the same | — |

The chase is a pointer chase — each load's address is the load before it — so
one walk cannot hide behind another. It is a straight line, not a loop: as a
loop, the branch closing it was mispredicted while cold, the machine with no
TLB waited on fetch where the walking one was waiting anyway, and every
difference came out a constant four or six cycles short.

Six descriptions are refused: no walk cost, no table anything looks up, ways
that do not divide the entries, a first level with a latency, a second level
with none, and a page that is not a power of two.

18/18 mutations caught: a data walk that costs nothing, ways ignored, every
table direct-mapped, no second level, a second-level hit that walks anyway, a
second level that costs nothing, first-in-first-out for least-recently-used,
a store's walk free on the execution-driven engine, a store translated again
at commit, a fetch walk free on each engine, a load counted when it executes
and again when it commits, counts never carried to commit, the page size
ignored, walks uncounted, a fetch miss counted when fetched, one table
serving both data and fetch, and fetch misses uncounted.

Four of the checks exist because a mutant survived without them: the three
pages eight apart (direct-mapped agreed with every ring of consecutive
pages), the hot page (a ring is used in the order it was filled, so the two
eviction orders agree), the one-entry machine (a store's second lookup hits
when there is room for its page), and the load of the code's own page (one
table for both looked the same whenever code and data sat on different
pages).

### What is not here

* **Translation itself.** Still timing: no entry is *read* for its contents,
  nothing faults, and a page the table has no entry for is walked like any
  other.
* **One address space.** No address-space identifiers, nothing flushed by a
  context switch; each hardware context of a shared core has a TLB of its
  own where a real core's threads share one.
* **The fetch TLB is looked up down a wrong path only where an instruction
  cache is declared**, since that is where wrong-path fetch is tracked.
* **SIMT cores** have no TLB; the clause is refused there.
* **A model that is not this library** is handed the core's `tlb` fields and
  does with them what it likes.

## 2a. TLB2 — the walker

```lisp
(tlb (data (entries 64) (ways 4)) (page-bytes 4096)
     (walkers 2)
     (walk (levels 4) (cycles 2) (table 0x40000000))
     (walk-cache (entries 16))
     (huge (bytes 2097152) (from 0x80000000) (to 0xC0000000)))
```

TLB1 said a walk costs `walk-cycles`, whatever it walked and however many
were going on at once. Four things a walk really is.

**`(walkers N)`.** A machine has one or two. A miss that finds them all busy
waits for the first to be free, and that walker is busy until the walk is
done. The walk is taken when the access is *made* -- when the load issues --
which is the cycle a walker is asked for; fetch's walk asks at the cycle of
the fetch. Unsaid, walks overlap without limit, as they did.

**`(walk (levels L) (cycles C) (table ADDR))`**, in place of `walk-cycles`. A
walk is L loads, each of the entry the one before pointed at, and those
entries are in memory -- so each is in the data cache or it is not. Every
level costs C, and whatever the cache charges for a line it does not hold.
The table is a radix tree over the page number, nine bits a level, laid out
from ADDR, each table found given the next 4096 bytes. So a program whose
pages are near each other finds the last level's line cached and walks
cheaply, one that strides across memory misses on it every time, and the
lines a walk brought in are in the cache afterwards in place of what was
there. Read through the machine's own data cache: not translated, and not
counted among the program's hits and misses -- charged in time.

**`(walk-cache (entries N))`.** The tables of the levels below the root, least
recently used out. A walk starts at the deepest level it holds and reads from
there down: after the first walk into a region, one read a page.

**`(huge (bytes B) (from A) (to Z))`.** A region mapped with large pages. An
address in it is on a page of B bytes, which one entry of every level that
remembers pages holds all of, and its walk stops a level short.

None is in the pack ABI: the counters are TLB1's, and a walk through a table
is still one `page_walks`.

### What holds it: `tlb_check.py`

The chase round six pages again, on both engines, each against the machine
translation is free on:

| Machine | Misses | Walks | Extra cycles |
|---|---|---|---|
| a table of three levels, four cycles each | 6 | 6 | 72: twelve a walk |
| ... and a walk cache | 6 | 6 | 32: twelve, then four a page |
| the six pages inside one large page | 1 | 1 | one walk |
| ... through the table | 1 | 1 | 8: a level short |
| the table, read through a data cache | 6 | 6 | 102: the first walk's three lines miss, the rest find them |

and six loads of six pages, none waiting for another: one walk's worth of
extra cycles where walks overlap, and 115 -- each after the first waiting out
the walk ahead of it -- with one walker.

9/9 mutations caught: walks that never wait, and a walker free the moment it
starts; a table read for nothing; a walk through a table that costs its
levels and no more; no walk cache, and one never filled; no large pages, and
a large page walked every level; and every level a new table every walk.
Three descriptions are refused: two costs for one walk, a walk cache over a
table of one level, and a large page no larger than a page.

The cache row found a bug before any mutant did: a table's name was packed
into the top of the word its place was stored in, so every table below the
root was a new table every walk, at a new address, and every walk missed
twice.

### What it is not

* **Entries read for what they say.** A level is a load of the right address;
  what is there is not looked at, so nothing is ever unmapped.
* **The table's own translation.** A walk's reads are not themselves
  translated, and a timed memory system (`memory-timing`) is asked for them
  as for any access.
* **Several sizes at once in one table**, a second level that holds only one
  size, and large pages chosen by anything but a declared region.
* **A wrong path's walks**, which keep no walker.

## 3. PF1 — a prefetcher the host brings

A cache of a described memory system names its prefetchers: `(prefetch stride
best-offset)`. Those three are the library's. PF1 lets a description name one
the library has never heard of and a host supply it, the way a core names a
predictor and `register_predictor` binds it.

```lisp
(defmemory l1d (kind cache) ... (mshrs 4) (prefetch acme.spp) (prefetch-degree 2))
```

```c
static int32_t observe(void *state, uint64_t line, uint64_t key, int32_t saw, uint64_t now,
                       uint64_t *fetch, int32_t max);
static const axis_sim_prefetcher SPP = { 1u, "acme.spp", create, destroy, observe };
S->register_prefetcher(&SPP);     /* how many caches name it; 0 is a typo */
S->select_core(m, "cpu0");        /* 0 until every named prefetcher is bound */
```

* **A namespaced name is one from outside.** `acme.spp` is a host's; a bare
  name that is not built in is a typo and validation refuses it. The rule is
  the predictor's, for the predictor's reason. A cache names at most one.
* **Unbound is refused.** `select_core` returns 0 for a core whose memory
  system names a prefetcher nobody has bound. A plausible number from a
  machine without the prefetcher it was described with is worse than a
  refusal.
* **It is shown every demand access** of the cache it is on, where the core
  has timed memory: the line, the key of the stream it belongs to (the
  instruction's address; 0 for a request from the level above), whether it
  hit, missed, or was the first use of a prefetched line, and the cycle.
  `create` is given the cache's line size and its declared `prefetch-degree`;
  each cache that names the prefetcher has a state of its own.
* **What it asks for is fetched by the library's own timed prefetch.** A line
  takes a miss buffer, waits in the prefetch queue or is dropped, goes
  through the levels below, and is counted a prefetch — and useful or not —
  exactly as a built-in one is. At most sixteen lines an access.

### What holds it: `prefetcher_check.py`

The example memory system, made non-coherent, one execution-driven core on
timed memory, two hundred loads.

| | cycles |
|---|---|
| a stride of 17 lines, no prefetcher | 17,100 |
| the same, built-in next-line of degree 2 | 16,908 |
| the same, a host's prefetcher that knows the stride | 4,710 |

* A host's next-line, written in the harness, takes exactly the cycles and
  leaves exactly the counters of the built-in at the same degree, on loads
  and on stores.
* One that asks for nothing is no prefetcher, to the cycle.
* It is shown as many misses as the cache counted, a first use for the
  prefetched lines then used, one key for the one load, and time that never
  runs backwards.
* Unbound, the core is not selected; a name no cache asks for binds to
  nothing; a bare unknown name, two names from outside on one cache, and one
  in a system with a SIMT port are refused by validation.

13/13 mutations caught: a miss never shown, a fetch timed from when the
access was asked rather than when it missed, a first use shown as a plain
hit, an unbound core selected, a stray name accepted, the key withheld, the
degree withheld, state never destroyed, only the first line asked for
fetched, only the first cache bound, a store's access not shown, a hit not
shown, and time stuck at zero. The last survived until the gate asked that
the final access be late in the run: "never runs backwards" is true of a
clock that never runs.

The stream is a pointer chase. As independent loads, the misses themselves
filled every miss buffer, each prefetch was dropped, and a prefetcher that
knew the stride exactly fetched three lines in two hundred — which is what
the model says a machine with four miss buffers and no prefetch queue does,
and no way to tell one prefetcher from another.

### What is not here

* **Timed memory only**, as stride and best-offset are: an untimed core's
  accesses are not shown to it.
* **No SIMT port.** A SIMT pack has no call to bind a prefetcher, so a system
  with one as a port may not name a prefetcher from outside — including the
  system a CPU pack creates and a SIMT machine then adopts, which would work.
* **It sees lines, not addresses or data**, so a pointer-chasing prefetcher
  that reads what was loaded cannot be written against it.
* **A prefetcher on the single cache a core names with `(memory ...)`**, as
  opposed to a described memory system, is still none: that cache has no
  prefetch at all.
