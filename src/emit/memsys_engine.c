/* The memory-system timing engine (docs/memory_system_design.md, MS4).
 *
 * Included whole into a simulator pack, beside the tables the description
 * generates. It knows nothing about any corpus: a system is a table of nodes,
 * and every behavior below is selected by a field a `defmemory` declared.
 *
 * THE CONTRACT -- `tools/memsys_model.py` is a second, independent reading of
 * it, and `tools/memsys_sim_check.py` holds the two to each other:
 *
 *   An access from a port (a core's first-level node) costs, in core cycles:
 *     - every cache level it reaches, that level's `latency-cycles`;
 *     - every step down, the round trip to the level below:
 *       2 x hops x (hop-cycles + router-cycles) on the declared topology;
 *     - at a DRAM, its controller's `latency-cycles` plus the row buffer's
 *       answer in DRAM cycles -- CL on a hit in the open row, tRCD + CL on an
 *       idle bank, tRP + tRCD + CL on a conflict (always tRCD + CL under a
 *       closed page) -- converted to core cycles, rounded up, through tCK and
 *       the system's `clock-ps`;
 *     - at a scratchpad, its `latency-cycles`.
 *   A miss at the last cache goes to the endpoint the ADDRESS MAP names for
 *   that address. An uncached region skips the caches and goes straight
 *   there from the port. An unmapped address costs nothing: it is not this
 *   memory system's to charge.
 *
 *   What is NOT charged, because a write buffer hides it: a write-back of a
 *   dirty victim, a write-through, a write that misses a no-write-allocate
 *   cache, a prefetch. Each still happens -- state below changes, a DRAM row
 *   opens -- and each is counted.
 *
 *   Replacement prefers the lowest-numbered invalid way; among valid ways,
 *   LRU takes the least recently used, FIFO the earliest filled, tree-PLRU
 *   follows the tree bits, and `random` a per-node xorshift32 seeded with
 *   0x9E3779B9 ^ node index, stepped once per victim choice, taken mod ways.
 *
 *   Inclusion: an inclusive level evicting a line invalidates it in every
 *   level above it on any port's path (a dirty copy up there is written back
 *   to the level below the evicting one). An exclusive level gives a line up
 *   when it serves it to the level above, and takes the victims that level
 *   evicts. `nine` does neither.
 *
 *   Prefetch next-line of degree d installs lines X+1 .. X+d at the level a
 *   demand miss of X occurred, without touching the levels below.
 *
 * COHERENCE (MS5). Under a protocol (`msi`, `mesi`, `moesi`), in a region
 * with a home H, the PORTS -- first-level caches, each a core's -- hold a
 * state per line: M, O, E or S. The directory is exact: it is which peer
 * ports (the other ports whose path passes H) hold the line. With ow(a, b)
 * one way, hops x (hop + router):
 *
 *   read, P holds the line: lat(P).
 *   read miss, a peer Q holds it M, O or E: Q forwards it --
 *     lat(P) + ow(P,H) + lat(H) + ow(H,Q) + lat(Q) + ow(Q,P);
 *     Q goes M->O under MOESI, M->S with a posted write-back under MSI and
 *     MESI, E->S, O stays O; P fills S.
 *   read miss, no owner: the path above; P fills E when no peer holds the
 *     line and the protocol has E, else S.
 *   write, P holds M: lat(P). E: lat(P), and M.
 *   write, P holds S or O (an upgrade): every peer copy is invalidated --
 *     lat(P) + ow(P,H) + lat(H) + inv + ow(H,P), inv the longest round trip
 *     H->R->H over the peers R holding it (0 if none); P becomes M.
 *   write miss, a peer Q owns it: lat(P) + ow(P,H) + lat(H) +
 *     max(ow(H,Q) + lat(Q) + ow(Q,P), inv' + ow(H,P)), inv' over the other
 *     holders; every peer copy is dropped; P fills M.
 *   write miss, no owner: the read path, plus inv over the sharers, which
 *     are dropped; P fills M.
 *   A directory lookup costs lat(H) and does not touch H's lines; a
 *   forwarding owner's recency is not updated. An M or O line leaving a port
 *   is written back as any dirty line is; E and S leave silently.
 *
 * NOT modelled, and said: MSHRs (a trace-driven model has one access in
 * flight), fabric contention, transient states and races (one access
 * completes before the next begins).
 *
 * TIMED ACCESSES (U1, docs/unified_engine_design.md §3). `axis_ms_access_at`
 * answers WHEN an access completes, for an engine that keeps time. It
 * charges everything above at the same points, and an access that meets
 * nothing busy completes exactly `axis_ms_access`'s cost after `now`. Then it
 * waits:
 *   - a hit on a line whose fill has not arrived completes when it arrives
 *     (a line is installed at its miss, with the time its data is back);
 *   - a miss at a cache declaring `mshrs` N takes the slot that frees first,
 *     waiting for it if all are busy, and holds it until its line arrives;
 *   - a DRAM bank is busy for its row operation and the line's burst (a row
 *     hit, the burst alone); a channel's bus carries one line at a time, for
 *     line-bytes / (2 x bus-bytes) DRAM clocks, at the END of the access -- so
 *     the burst is part of CL when nothing contends, and a wait when
 *     something does;
 *   - prefetches are timed fetches through the levels below. They take an
 *     MSHR -- waiting for the first to free in a queue of `prefetch-queue`
 *     slots (a slot is taken until its prefetch starts) and dropped when every
 *     MSHR and every slot is busy; with no queue, dropped at once -- banks
 *     and the bus. Next-line fetches X+1 .. X+d at a demand miss of X. Stride
 *     keeps 256 entries keyed by the caller's key (the first line of a request
 *     trains it; every line of a request with a trained stride fetches d
 *     strides ahead). Best-offset (Michaud) learns an offset from the arrival
 *     times of the level's own fills and fetches X+D .. X+D+d-1 at a demand
 *     miss or the first use of a prefetched line (a load's or a store's): offsets 1..64 with prime
 *     factors 2, 3, 5; score 31 or 100 rounds end a phase; a best score of 1
 *     or less turns it off; a 256-entry recent-requests table.
 *   Untimed accesses ignore all of this, stride and best-offset included, as
 *   they always have.
 *   Coherent regions are charged as untimed, with no waits.
 */

/* Every function is `static`: two packs in one process each carry a copy,
   and a shared symbol would bind both to whichever loaded first. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { AXIS_MS_CACHE = 0, AXIS_MS_DRAM = 1, AXIS_MS_SCRATCH = 2 };
enum { AXIS_MS_LRU = 0, AXIS_MS_PLRU = 1, AXIS_MS_FIFO = 2, AXIS_MS_RANDOM = 3 };
enum { AXIS_MS_NINE = 0, AXIS_MS_INCLUSIVE = 1, AXIS_MS_EXCLUSIVE = 2 };

typedef struct axis_ms_node_cfg {
  const char *name;
  const char *core;          /* "" for a shared node */
  int32_t kind;
  int32_t next;              /* index, -1 for an endpoint */
  uint32_t x, y;
  uint32_t latency;
  /* cache */
  uint32_t sets, ways, line_bytes;
  int32_t replacement, inclusion;
  int32_t write_back, write_allocate;
  uint32_t prefetch_degree;  /* next-line; 0 is none */
  /* dram */
  uint32_t banks, row_bytes, closed_page;
  uint32_t tck_ps, tcl, trcd, trp;
  /* Timed accesses only (U1). */
  uint32_t mshrs;            /* 0: unbounded */
  uint32_t prefetch_kinds;   /* bits: 1 next-line, 2 stride, 4 best-offset */
  uint32_t pf_degree;        /* every kind's degree */
  uint32_t channels, bus_bytes;
  uint32_t prefetch_queue;   /* prefetches that may wait for an MSHR; 0: none (dropped) */
  /* A prefetcher this file has not got, by the name a host binds one to
     (PF1); NULL or "" for none. Timed accesses only. */
  const char *prefetch_ext;
} axis_ms_node_cfg;
enum { AXIS_MS_PF_NEXT = 1, AXIS_MS_PF_STRIDE = 2, AXIS_MS_PF_BOP = 4 };
#define AXIS_MS_PF_ENTRIES 256u

typedef struct axis_ms_region_cfg {
  uint64_t base, size;
  int32_t target;
  int32_t uncached;
  int32_t home;              /* the directory, -1 outside coherence */
} axis_ms_region_cfg;

typedef struct axis_ms_system_cfg {
  const char *name;
  uint32_t clock_ps;
  int32_t topology;          /* 0 mesh, 1 torus, 2 ring, 3 crossbar */
  uint32_t cols, rows;
  uint32_t hop_cycles, router_cycles;
  int32_t node_count;
  const axis_ms_node_cfg *nodes;
  int32_t region_count;
  const axis_ms_region_cfg *regions;
  int32_t protocol;          /* 0 none, 1 msi, 2 mesi, 3 moesi */
} axis_ms_system_cfg;

typedef struct axis_ms_stats {
  uint64_t hits, misses, writebacks, evictions, prefetches, back_invalidations;
  uint64_t row_hits, row_idle, row_conflicts, accesses;
  uint64_t forwards, invalidations, upgrades;
  /* Timed accesses only (U1). */
  uint64_t fill_waits, mshr_waits, bank_waits, bus_waits;
  uint64_t prefetch_useful, prefetch_dropped, bop_offset, bop_rounds;
} axis_ms_stats;

typedef struct { uint64_t key, last; int64_t stride; int32_t conf; } axis_ms_stride_entry;

/* A prefetcher from outside (PF1), as this engine calls one. It is shown
   every demand access of the cache it is on -- the line, the stream's key (0:
   none), what happened and when -- and answers with lines to fetch, which
   are fetched as any prefetch is: an MSHR, the queue or a drop, the levels
   below. `create` is given the cache's line size and declared degree. */
enum { AXIS_MS_SAW_HIT = 0, AXIS_MS_SAW_MISS = 1, AXIS_MS_SAW_FIRST_USE = 2 };
#define AXIS_MS_EXT_LINES 16
typedef struct axis_ms_ext_prefetcher {
  void *(*create)(uint32_t line_bytes, uint32_t degree);
  void (*destroy)(void *state);
  int32_t (*observe)(void *state, uint64_t line, uint64_t key, int32_t saw, uint64_t now,
                     uint64_t *fetch, int32_t max);
} axis_ms_ext_prefetcher;

typedef struct axis_ms_node {
  uint64_t *tag;
  uint8_t *valid, *dirty;
  uint8_t *state;            /* a port's coherence state: 0 I, 1 S, 2 E, 3 O, 4 M */
  uint64_t *stamp;           /* LRU: last use; FIFO: fill */
  uint8_t *plru;             /* ways - 1 tree bits per set */
  uint32_t rng;
  int64_t *open_row;         /* per bank, -1 idle */
  axis_ms_stats stats;
  /* Timed accesses only (U1). */
  uint64_t *ready;           /* per line: when its data is here */
  uint8_t *pf;               /* per line: brought by a prefetch, not yet used */
  uint64_t *mshr_free;       /* per MSHR: when it frees */
  uint64_t *bank_free;       /* per DRAM bank */
  uint64_t *bus_free;        /* per DRAM channel */
  uint64_t *pq;              /* per prefetch-queue slot: when its prefetch starts */
  axis_ms_stride_entry *stride;
  uint64_t *bop_line, *bop_ready;
  uint32_t bop_score[64], bop_test, bop_round;
  int32_t bop_offset;
  axis_ms_ext_prefetcher ext;  /* bound by the library that owns this system */
  void *ext_state;
  int32_t ext_bound;
} axis_ms_node;

typedef struct axis_ms {
  /* Two libraries may share one system (U3: a CPU pack and a SIMT pack, each
     carrying this file): the one adopting another's checks this first, and
     refuses a system laid out by a different version of it. */
  uint32_t layout;
  const axis_ms_system_cfg *cfg;
  axis_ms_node *node;
  uint64_t clock;
  /* Machines sharing this system; the last to leave frees it. */
  int32_t refs;
  /* The timed access in progress (axis_ms_access_at): its start, the
     caller's key, whether it is the first line of its request. */
  int32_t timed;
  uint64_t t0, key;
  int32_t first;
  uint64_t line_bytes;       /* the system's one line size (validation holds it) */
} axis_ms;

#define AXIS_MS_LAYOUT ((uint32_t)(0x4D530000u ^ (sizeof(axis_ms) << 20) ^ (sizeof(axis_ms_node) << 8) \
                                   ^ sizeof(axis_ms_stats) ^ (sizeof(axis_ms_node_cfg) << 14)))

static uint32_t axis_ms_hops(const axis_ms_system_cfg *c, const axis_ms_node_cfg *a, const axis_ms_node_cfg *b) {
  uint32_t dx = a->x > b->x ? a->x - b->x : b->x - a->x;
  uint32_t dy = a->y > b->y ? a->y - b->y : b->y - a->y;
  switch (c->topology) {
    case 1: if (dx > c->cols - dx) dx = c->cols - dx; if (dy > c->rows - dy) dy = c->rows - dy; return dx + dy;
    case 2: if (dx > c->cols - dx) dx = c->cols - dx; return dx;
    case 3: return (a->x != b->x || a->y != b->y) ? 1u : 0u;
    default: return dx + dy;
  }
}

static uint64_t axis_ms_trip(const axis_ms *ms, int32_t from, int32_t to) {
  const axis_ms_system_cfg *c = ms->cfg;
  return 2ull * axis_ms_hops(c, &c->nodes[from], &c->nodes[to]) * (uint64_t)(c->hop_cycles + c->router_cycles);
}

static axis_ms *axis_ms_new(const axis_ms_system_cfg *cfg) {
  axis_ms *ms = calloc(1, sizeof *ms);
  if (!ms) return NULL;
  ms->layout = AXIS_MS_LAYOUT;
  ms->cfg = cfg;
  ms->refs = 1;
  ms->line_bytes = 64;
  for (int32_t k = 0; k < cfg->node_count; ++k)
    if (cfg->nodes[k].kind == AXIS_MS_CACHE && cfg->nodes[k].line_bytes) { ms->line_bytes = cfg->nodes[k].line_bytes; break; }
  ms->node = calloc((size_t)cfg->node_count, sizeof *ms->node);
  for (int32_t i = 0; i < cfg->node_count; ++i) {
    const axis_ms_node_cfg *n = &cfg->nodes[i];
    axis_ms_node *s = &ms->node[i];
    s->rng = 0x9E3779B9u ^ (uint32_t)i;
    if (n->kind == AXIS_MS_CACHE) {
      size_t lines = (size_t)n->sets * n->ways;
      s->tag = calloc(lines, sizeof *s->tag);
      s->valid = calloc(lines, 1);
      s->dirty = calloc(lines, 1);
      s->state = calloc(lines, 1);
      s->stamp = calloc(lines, sizeof *s->stamp);
      s->plru = calloc((size_t)n->sets * (n->ways ? n->ways : 1), 1);
      s->ready = calloc(lines, sizeof *s->ready);
      s->pf = calloc(lines, 1);
      s->mshr_free = calloc(n->mshrs ? n->mshrs : 1, sizeof *s->mshr_free);
      s->pq = calloc(n->prefetch_queue ? n->prefetch_queue : 1, sizeof *s->pq);
      if (n->prefetch_kinds & AXIS_MS_PF_STRIDE) s->stride = calloc(AXIS_MS_PF_ENTRIES, sizeof *s->stride);
      if (n->prefetch_kinds & AXIS_MS_PF_BOP) {
        s->bop_line = calloc(AXIS_MS_PF_ENTRIES, sizeof *s->bop_line);
        s->bop_ready = calloc(AXIS_MS_PF_ENTRIES, sizeof *s->bop_ready);
        s->bop_offset = 1;
      }
    } else if (n->kind == AXIS_MS_DRAM) {
      s->open_row = malloc(sizeof *s->open_row * (n->banks ? n->banks : 1));
      for (uint32_t b = 0; b < (n->banks ? n->banks : 1); ++b) s->open_row[b] = -1;
      s->bank_free = calloc(n->banks ? n->banks : 1, sizeof *s->bank_free);
      s->bus_free = calloc(n->channels ? n->channels : 1, sizeof *s->bus_free);
    }
  }
  return ms;
}

static void axis_ms_free(axis_ms *ms) {
  if (!ms || --ms->refs > 0) return;
  for (int32_t i = 0; i < ms->cfg->node_count; ++i) {
    axis_ms_node *s = &ms->node[i];
    free(s->tag); free(s->valid); free(s->dirty); free(s->state); free(s->stamp); free(s->plru); free(s->open_row);
    free(s->ready); free(s->pf); free(s->mshr_free); free(s->bank_free); free(s->bus_free); free(s->pq); free(s->stride);
    free(s->bop_line); free(s->bop_ready);
    if (s->ext_bound && s->ext.destroy && s->ext_state) s->ext.destroy(s->ext_state);
  }
  free(ms->node);
  free(ms);
}

/* Whether node `i` names a prefetcher from outside, and its name. */
static const char *axis_ms_ext_name(const axis_ms_system_cfg *cfg, int32_t i) {
  const char *name = cfg->nodes[i].prefetch_ext;
  return (cfg->nodes[i].kind == AXIS_MS_CACHE && name && name[0]) ? name : NULL;
}
/* Bind one to node `i`, with state of its own. */
static void axis_ms_bind_prefetcher(axis_ms *ms, int32_t i, const axis_ms_ext_prefetcher *ext) {
  axis_ms_node *s = &ms->node[i];
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  s->ext = *ext;
  s->ext_state = ext->create ? ext->create(n->line_bytes, n->pf_degree) : NULL;
  s->ext_bound = 1;
}

/* The port a core accesses through: its node with no node above it, i.e. the
   one naming the core. -1 when this system does not hold the core. */
static int32_t axis_ms_port(const axis_ms *ms, const char *core) {
  for (int32_t i = 0; i < ms->cfg->node_count; ++i)
    if (core && ms->cfg->nodes[i].core[0] && strcmp(ms->cfg->nodes[i].core, core) == 0) return i;
  return -1;
}

static int32_t axis_ms_region(const axis_ms *ms, uint64_t addr) {
  for (int32_t r = 0; r < ms->cfg->region_count; ++r) {
    const axis_ms_region_cfg *g = &ms->cfg->regions[r];
    if (addr >= g->base && addr - g->base < g->size) return r;
  }
  return -1;
}

/* ---- one cache level ------------------------------------------------------ */

static int32_t axis_ms_find(const axis_ms *ms, int32_t i, uint64_t line) {
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  const axis_ms_node *s = &ms->node[i];
  uint32_t base = (uint32_t)(line % n->sets) * n->ways;
  for (uint32_t w = 0; w < n->ways; ++w)
    if (s->valid[base + w] && s->tag[base + w] == line) return (int32_t)(base + w);
  return -1;
}

static void axis_ms_plru_touch(axis_ms *ms, int32_t i, uint32_t set, uint32_t way) {
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  uint8_t *bits = &ms->node[i].plru[(size_t)set * n->ways];
  uint32_t node = 0, lo = 0, hi = n->ways;
  while (hi - lo > 1) {
    uint32_t mid = (lo + hi) / 2;
    /* Point the bit AWAY from the way just used: 1 means "go right next". */
    if (way < mid) { bits[node] = 1; node = 2 * node + 1; hi = mid; }
    else { bits[node] = 0; node = 2 * node + 2; lo = mid; }
  }
}

static uint32_t axis_ms_plru_victim(const axis_ms *ms, int32_t i, uint32_t set) {
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  const uint8_t *bits = &ms->node[i].plru[(size_t)set * n->ways];
  uint32_t node = 0, lo = 0, hi = n->ways;
  while (hi - lo > 1) {
    uint32_t mid = (lo + hi) / 2;
    if (bits[node]) { node = 2 * node + 2; lo = mid; } else { node = 2 * node + 1; hi = mid; }
  }
  return lo;
}

static void axis_ms_used(axis_ms *ms, int32_t i, int32_t slot) {
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  axis_ms_node *s = &ms->node[i];
  if (n->replacement == AXIS_MS_LRU) s->stamp[slot] = ++ms->clock;
  if (n->replacement == AXIS_MS_PLRU) axis_ms_plru_touch(ms, i, (uint32_t)slot / n->ways, (uint32_t)slot % n->ways);
}

static uint32_t axis_ms_victim(axis_ms *ms, int32_t i, uint32_t set) {
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  axis_ms_node *s = &ms->node[i];
  uint32_t base = set * n->ways;
  for (uint32_t w = 0; w < n->ways; ++w) if (!s->valid[base + w]) return w;
  switch (n->replacement) {
    case AXIS_MS_PLRU: return axis_ms_plru_victim(ms, i, set);
    case AXIS_MS_RANDOM: {
      uint32_t x = s->rng; x ^= x << 13; x ^= x >> 17; x ^= x << 5; s->rng = x;
      return x % n->ways;
    }
    default: {
      uint32_t v = 0;
      for (uint32_t w = 1; w < n->ways; ++w) if (s->stamp[base + w] < s->stamp[base + v]) v = w;
      return v;
    }
  }
}

static void axis_ms_write_below(axis_ms *ms, int32_t i, uint64_t line, int32_t endpoint);

/* Every level above `i` on any path loses `line`; a dirty copy is written
   back to what is below `i`. */
static void axis_ms_back_invalidate(axis_ms *ms, int32_t i, uint64_t line, int32_t endpoint) {
  const axis_ms_system_cfg *c = ms->cfg;
  for (int32_t j = 0; j < c->node_count; ++j) {
    if (j == i || c->nodes[j].kind != AXIS_MS_CACHE) continue;
    int32_t k = c->nodes[j].next;
    int above = 0;
    while (k >= 0) { if (k == i) { above = 1; break; } k = c->nodes[k].next; }
    if (!above) continue;
    int32_t slot = axis_ms_find(ms, j, line);
    if (slot < 0) continue;
    if (ms->node[j].dirty[slot]) {
      ms->node[j].stats.writebacks++;
      axis_ms_write_below(ms, i, line, endpoint);
    }
    ms->node[j].valid[slot] = 0;
    ms->node[j].dirty[slot] = 0;
    ms->node[j].state[slot] = 0;
    ms->node[i].stats.back_invalidations++;
  }
}

static void axis_ms_endpoint_touch(axis_ms *ms, int32_t e, uint64_t addr, uint64_t *cost);

/* Install `line` at `i`, evicting as the policies say. Returns the slot. */
static int32_t axis_ms_fill(axis_ms *ms, int32_t i, uint64_t line, int dirty, int32_t endpoint) {
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  axis_ms_node *s = &ms->node[i];
  uint32_t set = (uint32_t)(line % n->sets);
  uint32_t way = axis_ms_victim(ms, i, set);
  int32_t slot = (int32_t)(set * n->ways + way);
  if (s->valid[slot]) {
    uint64_t old = s->tag[slot];
    int was_dirty = s->dirty[slot];
    s->stats.evictions++;
    s->valid[slot] = 0;
    s->dirty[slot] = 0;
    s->state[slot] = 0;
    if (n->inclusion == AXIS_MS_INCLUSIVE) axis_ms_back_invalidate(ms, i, old, endpoint);
    int32_t below = n->next;
    if (below >= 0 && ms->cfg->nodes[below].kind == AXIS_MS_CACHE
        && ms->cfg->nodes[below].inclusion == AXIS_MS_EXCLUSIVE) {
      /* An exclusive level below keeps what this one lets go. */
      int32_t there = axis_ms_find(ms, below, old);
      if (there < 0) there = axis_ms_fill(ms, below, old, was_dirty, endpoint);
      else if (was_dirty) ms->node[below].dirty[there] = 1;
      if (was_dirty) s->stats.writebacks++;
    } else if (was_dirty) {
      s->stats.writebacks++;
      axis_ms_write_below(ms, i, old, endpoint);
    }
  }
  s->valid[slot] = 1;
  s->dirty[slot] = (uint8_t)(dirty ? 1 : 0);
  s->state[slot] = 0;
  s->tag[slot] = line;
  s->ready[slot] = 0;  /* here now, unless a timed miss says when */
  s->pf[slot] = 0;
  if (n->replacement == AXIS_MS_FIFO) s->stamp[slot] = ++ms->clock;
  axis_ms_used(ms, i, slot);
  return slot;
}

/* A posted write of `line` into what is below `i`: the next cache, or the
   endpoint. State changes; nothing is charged. */
static void axis_ms_write_below(axis_ms *ms, int32_t i, uint64_t line, int32_t endpoint) {
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  int32_t below = n->next;
  if (below < 0) return;
  if (ms->cfg->nodes[below].kind != AXIS_MS_CACHE) {
    /* Posted, and free in a timed access too: write-back traffic takes no
       bank and no bus time (the contract). */
    uint64_t ignored = 0;
    int32_t timed = ms->timed;
    ms->timed = 0;
    axis_ms_endpoint_touch(ms, endpoint >= 0 ? endpoint : below, line * n->line_bytes, &ignored);
    ms->timed = timed;
    return;
  }
  const axis_ms_node_cfg *b = &ms->cfg->nodes[below];
  int32_t slot = axis_ms_find(ms, below, line);
  if (slot >= 0) {
    if (b->write_back) ms->node[below].dirty[slot] = 1;
    else axis_ms_write_below(ms, below, line, endpoint);
    axis_ms_used(ms, below, slot);
  } else if (b->write_allocate) {
    axis_ms_fill(ms, below, line, b->write_back, endpoint);
    if (!b->write_back) axis_ms_write_below(ms, below, line, endpoint);
  } else {
    axis_ms_write_below(ms, below, line, endpoint);
  }
}

/* ---- endpoints ------------------------------------------------------------ */

static void axis_ms_endpoint_touch(axis_ms *ms, int32_t e, uint64_t addr, uint64_t *cost) {
  const axis_ms_system_cfg *c = ms->cfg;
  const axis_ms_node_cfg *n = &c->nodes[e];
  axis_ms_node *s = &ms->node[e];
  s->stats.accesses++;
  if (n->kind != AXIS_MS_DRAM) { *cost += n->latency; return; }
  uint32_t banks = n->banks ? n->banks : 1;
  uint64_t row = addr / n->row_bytes;
  uint32_t bank = (uint32_t)(row % banks);
  int64_t id = (int64_t)(row / banks);
  uint64_t dram;
  if (n->closed_page) { dram = n->trcd + n->tcl; s->stats.row_idle++; }
  else if (s->open_row[bank] == id) { dram = n->tcl; s->stats.row_hits++; }
  else if (s->open_row[bank] < 0) { dram = n->trcd + n->tcl; s->stats.row_idle++; }
  else { dram = n->trp + n->trcd + n->tcl; s->stats.row_conflicts++; }
  uint64_t at = ms->t0 + *cost;
  if (ms->timed && s->bank_free[bank] > at) {
    /* The bank is still busy with an earlier access: this one waits. */
    *cost += s->bank_free[bank] - at;
    s->stats.bank_waits++;
  }
  uint64_t start = ms->t0 + *cost;
  if (!n->closed_page) s->open_row[bank] = id;
  uint64_t ps = dram * n->tck_ps;
  *cost += n->latency + (ps + c->clock_ps - 1) / c->clock_ps;
  if (ms->timed) {
    /* The line crosses the channel's bus at the end of the access; another
       line on that bus pushes it later. The bank is busy for its row
       operation (not CL: column accesses pipeline) and the burst. */
    uint32_t bus = n->bus_bytes ? n->bus_bytes : 8;
    uint64_t line_bytes = ms->line_bytes;
    uint64_t burst_tck = (line_bytes + 2 * bus - 1) / (2 * bus);
    uint64_t burst = (burst_tck * n->tck_ps + c->clock_ps - 1) / c->clock_ps;
    if (!burst) burst = 1;
    uint32_t channel = (uint32_t)((addr / line_bytes) % (n->channels ? n->channels : 1));
    uint64_t done = ms->t0 + *cost, xfer = done - (done - start >= burst ? burst : done - start);
    if (s->bus_free[channel] > xfer) {
      *cost += s->bus_free[channel] - xfer;
      s->stats.bus_waits++;
      xfer = s->bus_free[channel];
    }
    s->bus_free[channel] = xfer + burst;
    uint64_t row_op = dram - n->tcl;  /* tRCD and tRP, in DRAM clocks */
    s->bank_free[bank] = start + (row_op * n->tck_ps + c->clock_ps - 1) / c->clock_ps + burst;
  }
}

/* ---- timed prefetching (U1) ---------------------------------------------- */

static int32_t axis_ms_serve(axis_ms *ms, int32_t i, uint64_t line, int32_t endpoint, uint64_t *cost, int upward);

/* Fetch `line` into cache `i`, asked at `at`: through the levels below as a
   demand miss would go, without counting a demand at `i`. A prefetch never
   waits: with every MSHR busy it is dropped. Returns when the line is back,
   or 0 when nothing was fetched. */
static uint64_t axis_ms_prefetch(axis_ms *ms, int32_t i, uint64_t line, int32_t endpoint, uint64_t at) {
  const axis_ms_system_cfg *c = ms->cfg;
  const axis_ms_node_cfg *n = &c->nodes[i];
  axis_ms_node *s = &ms->node[i];
  if (axis_ms_find(ms, i, line) >= 0) return 0;
  int32_t mshr = -1;
  if (n->mshrs) {
    mshr = 0;
    for (uint32_t k = 1; k < n->mshrs; ++k) if (s->mshr_free[k] < s->mshr_free[mshr]) mshr = (int32_t)k;
    if (s->mshr_free[mshr] > at) {
      /* Every MSHR busy: wait in the prefetch queue for the first to free,
         if the queue has room (a slot whose prefetch has started); else drop. */
      int32_t q = -1;
      for (uint32_t k = 0; k < n->prefetch_queue; ++k) if (s->pq[k] <= at) { q = (int32_t)k; break; }
      if (q < 0) { s->stats.prefetch_dropped++; return 0; }
      at = s->mshr_free[mshr];
      s->pq[q] = at;
    }
  }
  uint64_t t0 = ms->t0, key = ms->key;
  ms->t0 = at;
  ms->key = 0;  /* a prefetch trains no stride */
  uint64_t cost = 0;
  int32_t below = n->next;
  int came_dirty = 0;
  if (below >= 0 && c->nodes[below].kind == AXIS_MS_CACHE) {
    cost += axis_ms_trip(ms, i, below);
    int32_t there = axis_ms_serve(ms, below, line, endpoint, &cost, 1);
    if (there >= 0 && c->nodes[below].inclusion == AXIS_MS_EXCLUSIVE) {
      came_dirty = ms->node[below].dirty[there];
      ms->node[below].valid[there] = 0;
      ms->node[below].dirty[there] = 0;
      ms->node[below].state[there] = 0;
    }
  } else if (below >= 0 || endpoint >= 0) {
    int32_t e = endpoint >= 0 ? endpoint : below;
    cost += axis_ms_trip(ms, i, e);
    axis_ms_endpoint_touch(ms, e, line * n->line_bytes, &cost);
  }
  uint64_t back = at + cost;
  ms->t0 = t0;
  ms->key = key;
  int32_t slot = axis_ms_fill(ms, i, line, came_dirty, endpoint);
  s->ready[slot] = back;
  s->pf[slot] = 1;
  if (mshr >= 0) s->mshr_free[mshr] = back;
  s->stats.prefetches++;
  return back;
}

/* ⚠️ A prefetcher from outside sees a demand access and says what to fetch.
   What it asks for goes through `axis_ms_prefetch` and nowhere else, so its
   fetches meet the MSHRs, the queue and the levels below exactly as the
   built-in ones' do -- and a line it asks for that is already here is not
   fetched, as theirs is not. */
static void axis_ms_ext_saw(axis_ms *ms, int32_t i, uint64_t line, int32_t endpoint, int32_t saw, uint64_t at) {
  axis_ms_node *s = &ms->node[i];
  if (!s->ext_bound || !s->ext.observe) return;
  uint64_t fetch[AXIS_MS_EXT_LINES];
  int32_t n = s->ext.observe(s->ext_state, line, ms->key, saw, at, fetch, AXIS_MS_EXT_LINES);
  if (n > AXIS_MS_EXT_LINES) n = AXIS_MS_EXT_LINES;
  for (int32_t k = 0; k < n; ++k) axis_ms_prefetch(ms, i, fetch[k], endpoint, at);
}

/* Stride: a request's first line trains the entry for the caller's key --
   two moves by the same stride in a row and it fires -- and every line of a
   request whose entry has fired fetches `degree` strides ahead. */
static void axis_ms_stride(axis_ms *ms, int32_t i, uint64_t line, int32_t endpoint) {
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  axis_ms_node *s = &ms->node[i];
  uint64_t key = ms->key;
  uint64_t h = key * 0x9e3779b97f4a7c15ull;
  h ^= h >> 29;
  axis_ms_stride_entry *e = &s->stride[(h * 0xbf58476d1ce4e5b9ull >> 32) & (AXIS_MS_PF_ENTRIES - 1)];
  if (ms->first) {
    if (e->key != key) { e->key = key; e->last = line; e->stride = 0; e->conf = 0; return; }
    int64_t d = (int64_t)(line - e->last);
    if (d && d == e->stride) { if (e->conf < 3) ++e->conf; } else { e->stride = d; e->conf = 0; }
    e->last = line;
  } else if (e->key != key) {
    return;
  }
  if (e->conf < 1 || !e->stride) return;
  uint64_t at = ms->t0;
  for (uint32_t k = 1; k <= n->pf_degree; ++k)
    axis_ms_prefetch(ms, i, line + (uint64_t)(e->stride * (int64_t)k), endpoint, at);
}

/* Best-offset (Michaud, "A Best-Offset Prefetcher", DPC-2 2015). */
static const int32_t axis_ms_bop_offsets[] = { 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 15, 16, 18, 20, 24, 25,
                                               27, 30, 32, 36, 40, 45, 48, 50, 54, 60, 64 };
#define AXIS_MS_BOP_N ((uint32_t)(sizeof axis_ms_bop_offsets / sizeof axis_ms_bop_offsets[0]))
static uint32_t axis_ms_bop_slot(uint64_t line) {
  uint64_t h = line * 0x9e3779b97f4a7c15ull;
  return (uint32_t)((h ^ (h >> 31)) & (AXIS_MS_PF_ENTRIES - 1));
}
static void axis_ms_bop_record(axis_ms_node *s, uint64_t base, uint64_t ready) {
  uint32_t k = axis_ms_bop_slot(base);
  s->bop_line[k] = base + 1;  /* +1: zero means empty */
  s->bop_ready[k] = ready;
}
static void axis_ms_bop_learn(axis_ms_node *s, uint64_t line, uint64_t now) {
  int32_t d = axis_ms_bop_offsets[s->bop_test];
  if (line > (uint64_t)d) {
    uint64_t base = line - (uint64_t)d;
    uint32_t k = axis_ms_bop_slot(base);
    if (s->bop_line[k] == base + 1 && s->bop_ready[k] <= now) ++s->bop_score[s->bop_test];
  }
  uint32_t best = 0;
  for (uint32_t k = 1; k < AXIS_MS_BOP_N; ++k) if (s->bop_score[k] > s->bop_score[best]) best = k;
  int end = s->bop_score[best] >= 31u;
  if (++s->bop_test == AXIS_MS_BOP_N) { s->bop_test = 0; end |= ++s->bop_round >= 100u; }
  if (!end) return;
  s->bop_offset = s->bop_score[best] > 1u ? axis_ms_bop_offsets[best] : 0;
  s->stats.bop_offset = (uint64_t)s->bop_offset;
  s->stats.bop_rounds++;
  memset(s->bop_score, 0, sizeof s->bop_score);
  s->bop_round = 0;
  s->bop_test = 0;
}
/* A trigger: a demand miss at `line`, or the first use of a prefetched line. */
static void axis_ms_bop_trigger(axis_ms *ms, int32_t i, uint64_t line, int32_t endpoint, uint64_t now) {
  const axis_ms_node_cfg *n = &ms->cfg->nodes[i];
  axis_ms_node *s = &ms->node[i];
  axis_ms_bop_learn(s, line, now);
  if (!s->bop_offset) return;
  for (uint32_t k = 0; k < n->pf_degree; ++k) {
    uint64_t pl = line + (uint64_t)s->bop_offset + k;
    uint64_t back = axis_ms_prefetch(ms, i, pl, endpoint, now);
    if (back) axis_ms_bop_record(s, pl - (uint64_t)s->bop_offset, back);
  }
}

/* ---- an access ------------------------------------------------------------ */

/* Serve `line` at cache `i` for a read (or a write-allocate fill), adding
   what it costs. Returns the slot it now occupies at `i`, or -1 when the line
   passed through without being kept (an exclusive level serving upward). */
static int32_t axis_ms_serve(axis_ms *ms, int32_t i, uint64_t line, int32_t endpoint, uint64_t *cost, int upward) {
  const axis_ms_system_cfg *c = ms->cfg;
  const axis_ms_node_cfg *n = &c->nodes[i];
  axis_ms_node *s = &ms->node[i];
  *cost += n->latency;
  if (ms->timed && (n->prefetch_kinds & AXIS_MS_PF_STRIDE) && ms->key && !upward)
    axis_ms_stride(ms, i, line, endpoint);
  int32_t slot = axis_ms_find(ms, i, line);
  if (slot >= 0) {
    s->stats.hits++;
    axis_ms_used(ms, i, slot);
    if (ms->timed) {
      if (s->ready[slot] > ms->t0 + *cost) {
        /* In flight: the data comes when its fill does. */
        *cost = s->ready[slot] - ms->t0;
        s->stats.fill_waits++;
      }
      int first_use = s->pf[slot];
      if (s->pf[slot]) {
        s->pf[slot] = 0;
        s->stats.prefetch_useful++;
        if (n->prefetch_kinds & AXIS_MS_PF_BOP) axis_ms_bop_trigger(ms, i, line, endpoint, ms->t0);
      }
      if (s->ext_bound) {
        axis_ms_ext_saw(ms, i, line, endpoint, first_use ? AXIS_MS_SAW_FIRST_USE : AXIS_MS_SAW_HIT, ms->t0);
        slot = axis_ms_find(ms, i, line);  /* a fetch may have moved it */
      }
    }
    return slot;
  }
  s->stats.misses++;
  int32_t mshr = -1;
  if (ms->timed && n->mshrs) {
    mshr = 0;
    for (uint32_t k = 1; k < n->mshrs; ++k) if (s->mshr_free[k] < s->mshr_free[mshr]) mshr = (int32_t)k;
    if (s->mshr_free[mshr] > ms->t0 + *cost) {
      *cost = s->mshr_free[mshr] - ms->t0;
      s->stats.mshr_waits++;
    }
  }
  uint64_t miss_at = ms->t0 + *cost;
  /* ⚠️ An exclusive level serving the level above does not keep what it
     fetches: the line goes up, and filling it here first would evict a line
     that has nothing to do with this access. */
  int keep = !(upward && n->inclusion == AXIS_MS_EXCLUSIVE);
  int32_t below = n->next;
  int came_dirty = 0;
  if (below >= 0 && c->nodes[below].kind == AXIS_MS_CACHE) {
    *cost += axis_ms_trip(ms, i, below);
    int32_t there = axis_ms_serve(ms, below, line, endpoint, cost, 1);
    if (there >= 0 && c->nodes[below].inclusion == AXIS_MS_EXCLUSIVE) {
      /* Exclusive: the line moves up, and its dirtiness with it. */
      came_dirty = ms->node[below].dirty[there];
      ms->node[below].valid[there] = 0;
      ms->node[below].dirty[there] = 0;
      ms->node[below].state[there] = 0;
    }
  } else {
    int32_t e = endpoint >= 0 ? endpoint : below;
    *cost += axis_ms_trip(ms, i, e);
    axis_ms_endpoint_touch(ms, e, line * n->line_bytes, cost);
  }
  if (!keep) return -1;
  slot = axis_ms_fill(ms, i, line, came_dirty, endpoint);
  if (ms->timed) {
    s->ready[slot] = ms->t0 + *cost;
    s->pf[slot] = 0;
    if (mshr >= 0) s->mshr_free[mshr] = s->ready[slot];
    if (n->prefetch_kinds & AXIS_MS_PF_BOP) {
      /* With prefetching off, a demand fill is recorded as itself, so a
         learning phase can still find an offset and turn it back on. */
      if (!s->bop_offset) axis_ms_bop_record(s, line, s->ready[slot]);
      axis_ms_bop_trigger(ms, i, line, endpoint, ms->t0);
    }
    if (n->prefetch_kinds & AXIS_MS_PF_NEXT)
      for (uint32_t k = 1; k <= n->pf_degree; ++k) axis_ms_prefetch(ms, i, line + k, endpoint, miss_at);
    axis_ms_ext_saw(ms, i, line, endpoint, AXIS_MS_SAW_MISS, miss_at);
  } else {
    for (uint32_t k = 1; k <= n->prefetch_degree; ++k) {
      if (axis_ms_find(ms, i, line + k) < 0) {
        axis_ms_fill(ms, i, line + k, 0, endpoint);
        s->stats.prefetches++;
      }
    }
  }
  slot = axis_ms_find(ms, i, line);
  return slot;
}

/* ---- coherence ------------------------------------------------------------ */

enum { AXIS_MS_I = 0, AXIS_MS_S = 1, AXIS_MS_E = 2, AXIS_MS_O = 3, AXIS_MS_M = 4 };

static uint64_t axis_ms_ow(const axis_ms *ms, int32_t a, int32_t b) {
  const axis_ms_system_cfg *c = ms->cfg;
  return (uint64_t)axis_ms_hops(c, &c->nodes[a], &c->nodes[b]) * (uint64_t)(c->hop_cycles + c->router_cycles);
}

/* A port other than `port` whose path passes `home`. */
static int axis_ms_peer(const axis_ms *ms, int32_t j, int32_t port, int32_t home) {
  const axis_ms_system_cfg *c = ms->cfg;
  if (j == port || c->nodes[j].kind != AXIS_MS_CACHE || !c->nodes[j].core[0]) return 0;
  for (int32_t k = c->nodes[j].next; k >= 0; k = c->nodes[k].next) if (k == home) return 1;
  return 0;
}

static void axis_ms_drop(axis_ms *ms, int32_t j, int32_t slot) {
  ms->node[j].valid[slot] = 0;
  ms->node[j].dirty[slot] = 0;
  ms->node[j].state[slot] = 0;
  ms->node[j].stats.invalidations++;
}

static uint64_t axis_ms_coherent(axis_ms *ms, int32_t port, uint64_t addr, int is_write, int32_t endpoint, int32_t home) {
  const axis_ms_system_cfg *c = ms->cfg;
  const axis_ms_node_cfg *n = &c->nodes[port];
  axis_ms_node *p = &ms->node[port];
  int32_t protocol = c->protocol;
  uint64_t line = addr / n->line_bytes;
  uint64_t cost = 0;
  /* The owner among the peers -- M, O, or E where the protocol has it -- and
     the longest invalidation round trip over every peer holding the line,
     and over every one but the owner. */
  int32_t owner = -1, owner_slot = -1, holders = 0;
  uint64_t inv_all = 0, inv_others = 0;
  for (int32_t j = 0; j < c->node_count; ++j) {
    if (!axis_ms_peer(ms, j, port, home)) continue;
    int32_t slot = axis_ms_find(ms, j, line);
    if (slot < 0) continue;
    holders++;
    uint8_t st = ms->node[j].state[slot];
    uint64_t trip = 2 * axis_ms_ow(ms, home, j);
    if (trip > inv_all) inv_all = trip;
    if (st == AXIS_MS_M || st == AXIS_MS_O || st == AXIS_MS_E) { owner = j; owner_slot = slot; }
  }
  for (int32_t j = 0; j < c->node_count; ++j) {
    if (j == owner || !axis_ms_peer(ms, j, port, home) || axis_ms_find(ms, j, line) < 0) continue;
    uint64_t trip = 2 * axis_ms_ow(ms, home, j);
    if (trip > inv_others) inv_others = trip;
  }
  int32_t slot = axis_ms_find(ms, port, line);
  if (!is_write) {
    if (slot >= 0) { p->stats.hits++; axis_ms_used(ms, port, slot); return n->latency; }
    if (owner >= 0) {
      p->stats.misses++;
      cost = n->latency + axis_ms_ow(ms, port, home) + c->nodes[home].latency
           + axis_ms_ow(ms, home, owner) + c->nodes[owner].latency + axis_ms_ow(ms, owner, port);
      axis_ms_node *q = &ms->node[owner];
      q->stats.forwards++;
      uint8_t st = q->state[owner_slot];
      if (st == AXIS_MS_M && protocol == 3) { q->state[owner_slot] = AXIS_MS_O; }
      else if (st == AXIS_MS_M) {
        q->state[owner_slot] = AXIS_MS_S; q->dirty[owner_slot] = 0;
        q->stats.writebacks++;
        axis_ms_write_below(ms, owner, line, endpoint);
      } else if (st == AXIS_MS_E) { q->state[owner_slot] = AXIS_MS_S; }
      int32_t mine = axis_ms_fill(ms, port, line, 0, endpoint);
      p->state[mine] = AXIS_MS_S;
      return cost;
    }
    axis_ms_serve(ms, port, line, endpoint, &cost, 0);
    int32_t mine = axis_ms_find(ms, port, line);
    if (mine >= 0) p->state[mine] = (holders == 0 && protocol >= 2) ? AXIS_MS_E : AXIS_MS_S;
    return cost;
  }
  if (slot >= 0) {
    p->stats.hits++;
    axis_ms_used(ms, port, slot);
    uint8_t st = p->state[slot];
    if (st == AXIS_MS_M || st == AXIS_MS_E) { p->state[slot] = AXIS_MS_M; p->dirty[slot] = 1; return n->latency; }
    p->stats.upgrades++;
    cost = n->latency + axis_ms_ow(ms, port, home) + c->nodes[home].latency + inv_all + axis_ms_ow(ms, home, port);
    for (int32_t j = 0; j < c->node_count; ++j) {
      if (!axis_ms_peer(ms, j, port, home)) continue;
      int32_t there = axis_ms_find(ms, j, line);
      if (there >= 0) axis_ms_drop(ms, j, there);
    }
    p->state[slot] = AXIS_MS_M; p->dirty[slot] = 1;
    return cost;
  }
  if (owner >= 0) {
    p->stats.misses++;
    uint64_t fwd = axis_ms_ow(ms, home, owner) + c->nodes[owner].latency + axis_ms_ow(ms, owner, port);
    uint64_t inv = inv_others + axis_ms_ow(ms, home, port);
    cost = n->latency + axis_ms_ow(ms, port, home) + c->nodes[home].latency + (fwd > inv ? fwd : inv);
    ms->node[owner].stats.forwards++;
    for (int32_t j = 0; j < c->node_count; ++j) {
      if (!axis_ms_peer(ms, j, port, home)) continue;
      int32_t there = axis_ms_find(ms, j, line);
      if (there >= 0) axis_ms_drop(ms, j, there);
    }
    int32_t mine = axis_ms_fill(ms, port, line, 1, endpoint);
    p->state[mine] = AXIS_MS_M;
    return cost;
  }
  axis_ms_serve(ms, port, line, endpoint, &cost, 0);
  cost += inv_all;
  for (int32_t j = 0; j < c->node_count; ++j) {
    if (!axis_ms_peer(ms, j, port, home)) continue;
    int32_t there = axis_ms_find(ms, j, line);
    if (there >= 0) axis_ms_drop(ms, j, there);
  }
  int32_t mine = axis_ms_find(ms, port, line);
  if (mine >= 0) { p->state[mine] = AXIS_MS_M; p->dirty[mine] = 1; }
  return cost;
}

/* What one access costs, in core cycles. */
static uint64_t axis_ms_access(axis_ms *ms, int32_t port, uint64_t addr, int is_write) {
  const axis_ms_system_cfg *c = ms->cfg;
  if (port < 0) return 0;
  int32_t r = axis_ms_region(ms, addr);
  if (r < 0) return 0;
  const axis_ms_region_cfg *g = &c->regions[r];
  uint64_t cost = 0;
  if (g->uncached) {
    cost += axis_ms_trip(ms, port, g->target);
    axis_ms_endpoint_touch(ms, g->target, addr, &cost);
    return cost;
  }
  const axis_ms_node_cfg *n = &c->nodes[port];
  if (c->protocol && g->home >= 0 && n->core[0]) {
    /* Coherence is charged as untimed, timed access or not (the contract). */
    int32_t timed = ms->timed;
    ms->timed = 0;
    uint64_t r = axis_ms_coherent(ms, port, addr, is_write, g->target, g->home);
    ms->timed = timed;
    return r;
  }
  uint64_t line = addr / n->line_bytes;
  if (!is_write) {
    axis_ms_serve(ms, port, line, g->target, &cost, 0);
    return cost;
  }
  int32_t slot = axis_ms_find(ms, port, line);
  if (slot < 0 && !n->write_allocate) {
    /* Posted around this level: counted as a miss, charged its lookup only. */
    cost += n->latency;
    ms->node[port].stats.misses++;
    axis_ms_write_below(ms, port, line, g->target);
    return cost;
  }
  if (slot < 0) slot = axis_ms_serve(ms, port, line, g->target, &cost, 0);
  else {
    cost += n->latency;
    ms->node[port].stats.hits++;
    axis_ms_used(ms, port, slot);
    if (ms->timed) {
      /* A store is a use like a load: it trains a stride, waits for a fill
         and is the first use of a prefetched line. */
      axis_ms_node *s = &ms->node[port];
      if ((n->prefetch_kinds & AXIS_MS_PF_STRIDE) && ms->key) axis_ms_stride(ms, port, line, g->target);
      slot = axis_ms_find(ms, port, line);  /* a stride prefetch may have moved it */
      if (s->ready[slot] > ms->t0 + cost) {
        cost = s->ready[slot] - ms->t0;
        s->stats.fill_waits++;
      }
      int first_use = s->pf[slot];
      if (s->pf[slot]) {
        s->pf[slot] = 0;
        s->stats.prefetch_useful++;
        if (n->prefetch_kinds & AXIS_MS_PF_BOP) axis_ms_bop_trigger(ms, port, line, g->target, ms->t0);
        slot = axis_ms_find(ms, port, line);
      }
      if (s->ext_bound) {
        axis_ms_ext_saw(ms, port, line, g->target, first_use ? AXIS_MS_SAW_FIRST_USE : AXIS_MS_SAW_HIT, ms->t0);
        slot = axis_ms_find(ms, port, line);
      }
    }
  }
  if (n->write_back) ms->node[port].dirty[slot] = 1;
  else axis_ms_write_below(ms, port, line, g->target);
  return cost;
}

/* A timed access (U1; the contract's TIMED ACCESSES): the cycle at which its
   data is available, starting at `now`. `key` names the stream for a stride
   prefetcher (0: none) and `first` says this is the first line of a request
   that may touch several. */
static uint64_t axis_ms_access_at(axis_ms *ms, int32_t port, uint64_t addr, int is_write, uint64_t now,
                                  uint64_t key, int first) {
  ms->timed = 1;
  ms->t0 = now;
  ms->key = key;
  ms->first = first;
  uint64_t cost = axis_ms_access(ms, port, addr, is_write);
  ms->timed = 0;
  ms->key = 0;
  return now + cost;
}

static const axis_ms_stats *axis_ms_stats_of(const axis_ms *ms, int32_t node) {
  return (node >= 0 && node < ms->cfg->node_count) ? &ms->node[node].stats : NULL;
}

/* A timed access's stall (U3): how far past `now` plus a hit in the port's
   own level its data arrives. An uncached or unmapped access has no first
   level, and stalls for all of it. */
static uint64_t axis_ms_stall_at(axis_ms *ms, int32_t port, uint64_t addr, int is_write, uint64_t now,
                                 uint64_t key) {
  if (port < 0) return 0;
  int32_t r = axis_ms_region(ms, addr);
  uint64_t done = axis_ms_access_at(ms, port, addr, is_write, now, key ? key : 1, 1);
  uint64_t hit = (r < 0 || ms->cfg->regions[r].uncached) ? 0 : ms->cfg->nodes[port].latency;
  return done > now + hit ? done - now - hit : 0;
}

/* What an access costs BEYOND a hit in the port's own level: the part a
   simulator charges as a stall, since an instruction's declared latency is
   already its cost when the first level has the line. An uncached or
   unmapped access has no first level to have hit in. */
static uint64_t axis_ms_stall(axis_ms *ms, int32_t port, uint64_t addr, int is_write) {
  if (port < 0) return 0;
  int32_t r = axis_ms_region(ms, addr);
  uint64_t cost = axis_ms_access(ms, port, addr, is_write);
  if (r < 0 || ms->cfg->regions[r].uncached) return cost;
  uint64_t hit = ms->cfg->nodes[port].latency;
  return cost > hit ? cost - hit : 0;
}
