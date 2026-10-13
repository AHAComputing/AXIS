/* ---- the SIMT engine (docs/simt_design.md) ---------------------------------
   Included verbatim by `emit-pack-simt-c` after one description's tables:
   AXIS_SIMT_OPS, AXIS_SIMT_CLASSES, AXIS_SIMT_CORES, and the pack accessors
   axis_simt_L() / axis_simt_E().

   A warp machine, timed and executed together:

     every cycle, up to issue-width warps are chosen (gto or rr) among those
     whose next instruction has its operands ready and a free unit; the chosen
     instruction EXECUTES THEN, in every active lane, through the generated
     executor -- so the architecture is the description's, lane by lane --
     and the warp-level part of a SIMT instruction (push, pop, mask, barrier)
     is applied from what its lanes computed.

   ⚠️ Execution at issue, in order per warp, with memory written at issue:
   the warps' memory accesses interleave in issue order, which is one
   sequentially consistent order. A host whose reads have side effects sees
   them in that order.

   ⚠️ What is NOT modelled, stated so that no number is read as covering it:
   the instruction cache and fetch bandwidth (a warp's next instruction is
   fetched the cycle it may issue); bank conflicts; MSHR limits (a coalesced
   request's lines go to the cache one per cycle, without bound on how many
   are outstanding); write-back traffic. */

#define AXIS_SIMT_MAX_WARPS 64
#define AXIS_SIMT_MAX_LANES 64
#define AXIS_SIMT_MAX_STACK 64
#define AXIS_SIMT_MAX_BARRIERS 64
#define AXIS_SIMT_MAX_DEPS 24
#define AXIS_SIMT_MAX_LINES (AXIS_SIMT_MAX_LANES * 8)
#define AXIS_SIMT_DECODE_CACHE 4096u
#define AXIS_SIMT_MAX_UNITS 16
#define AXIS_SIMT_MAX_COPIES 16
/* Where a cross-lane instruction sees the other lanes: region r is 64 KiB at
   AXIS_SIMT_XLANE_BASE + (r << 16), 8 bytes a lane, lane 0 first. Regions
   0..7 are the instruction's lane-class sources in operand order; 8.. are
   the core's lane-state slots in the order the ISA declares them. */
#define AXIS_SIMT_XLANE_BASE 0xffff000000000000ull
#define AXIS_SIMT_XLANE_REGIONS 16
#define AXIS_SIMT_UOP_LINES (AXIS_SIMT_MAX_LANES * 2)
#define AXIS_SIMT_UOP_DEPS (AXIS_SIMT_MAX_DEPS * 2)
#define AXIS_SIMT_STORE_TABLE 4096u

typedef struct {
  uint64_t orig_mask;  /* the warp's mask when it split */
  uint64_t else_pc;    /* where the other group resumes: the SPLIT's next pc */
  int fallthrough;     /* the other group has run; the next JOIN pops */
} axis_simt_ipdom;

typedef struct {
  uint32_t word;
  int32_t valid;
  int32_t index;                 /* lift index */
  const char *isa;
  const axis_simt_op *op;        /* NULL: decoded, but the description gives it no timing row */
  int32_t role;
  int32_t unit;                  /* index into the core's units */
  int32_t nsrc, ndst;
  int32_t src[AXIS_SIMT_MAX_DEPS];   /* register slot, or 1000+state slot */
  int32_t dst[AXIS_SIMT_MAX_DEPS];
  axis_pack_lifted lifted;
  int32_t sys_dst_slot;          /* sysread: the destination slot, -1 for the zero register */
  uint32_t latency;              /* the core's mnemonic-latency override, 0 for none */
  uint32_t sys_index;            /* sysread: the register index */
  /* vector mode */
  int32_t vec;                   /* an instruction of the core's vector ISA */
  int32_t bcast;                 /* ... whose sources are lane 0's */
  int32_t pflags;                /* ... that sets the thread's flags from every lane */
  int32_t call, ret;             /* implicit divergence: counts toward a lane's call depth */
  int32_t yield;                 /* ... a reconvergence hint */
  int32_t relax;                 /* ... a spin-loop hint: sets the running path aside */
  int32_t wfe, sev, sevl;        /* ... events: wait, send, send to oneself */
  int32_t xlane;                 /* ... that reads other lanes' slices */
  int32_t sum;                   /* ... whose result is the lanes' parts summed */
  int32_t wide;                  /* names a register wider than a lane's slice */
  uint32_t src_lane, dst_lane;   /* which src[] / dst[] are lane-class registers */
} axis_simt_decoded;

/* Out of order: an instruction the warp has dispatched -- executed, in
   program order -- and that has not yet been through a unit. */
typedef struct {
  int32_t unit;
  uint32_t occupancy, latency, unit_latency;
  int32_t ndep;
  uint64_t dep[AXIS_SIMT_UOP_DEPS];   /* the dispatches it waits for, by number */
  int32_t ndst;
  int32_t dst[AXIS_SIMT_MAX_DEPS];
  uint32_t nlines;
  uint64_t lines[AXIS_SIMT_UOP_LINES];
  int32_t issued;
  uint64_t done;
  int32_t front;                      /* the front end waits for its outcome */
  uint64_t key;                       /* (warp, pc), for the prefetcher */
  uint64_t lanes;                     /* the lanes it ran for (path-issue smt) */
  int32_t write;                      /* its lines are a store's */
} axis_simt_uop;

typedef struct {
  int32_t active;
  uint64_t pc, mask;
  uint32_t depth;
  axis_simt_ipdom stack[AXIS_SIMT_MAX_STACK];
  uint64_t ready_at;       /* the cycle its next instruction may issue */
  uint64_t inflight_until; /* when everything it issued has completed */
  int32_t waiting_bar;     /* barrier id + 1, or 0 */
  int32_t draining;        /* WSYNC: waiting for inflight_until */
  int32_t vector;          /* one thread whose vector registers span the lanes */
  /* Implicit divergence: the paths that are not running. */
  uint32_t npaths;
  uint64_t path_pc[AXIS_SIMT_MAX_LANES], path_mask[AXIS_SIMT_MAX_LANES];
  int32_t calldepth[AXIS_SIMT_MAX_LANES];
  /* Threads an OS placed: which lanes may share a path (axis_simt_lane_in). */
  uint32_t tag[AXIS_SIMT_MAX_LANES];
  /* Forward progress, (progress N): instructions the running path has issued
     in a row while another waited; per lane, when its path was set aside
     (0: not set aside). */
  uint32_t stint;
  uint64_t aside[AXIS_SIMT_MAX_LANES];
  uint64_t parked_at[AXIS_SIMT_MAX_LANES];  /* when its path was last parked */
  /* Events, (events ...): each lane's event register; lanes asleep at a
     wait; whether every path of the warp sleeps (it issues nothing). */
  uint64_t event, asleep;
  int32_t dormant;
  /* (path-issue smt): when each lane's front end may go on (a path is ready
     when all its lanes are), and who last wrote each register, per lane. */
  uint64_t front_ready[AXIS_SIMT_MAX_LANES];
  uint64_t spawn_pc;         /* a WSPAWN that found the warp still retiring: start it here when it has (0: none) */
  uint64_t *lreg_writer;     /* [lane][slot] */
  uint64_t *lstate_writer;   /* [lane][64] */
  /* Out of order: the window, numbered by dispatch; who last wrote each
     register slot and state slot (dispatch number + 1, 0 for nobody). */
  axis_simt_uop *rob;
  uint64_t rob_head, rob_next;
  uint64_t *reg_writer;
  uint64_t state_writer[64];
  /* Memory as an ordering: the last store dispatched to each 8 bytes, direct
     mapped (a collision forgets the older store: the model errs fast). */
  uint64_t *store_at, *store_seq;
  uint64_t started;        /* for greedy-then-oldest: age */
  uint64_t *reg_ready;     /* per register slot */
  uint64_t state_ready[64];
} axis_simt_warp;

typedef struct {
  uint64_t tag;
  uint64_t lru;
  uint64_t ready;   /* when its data arrives (with track-fills) */
  int32_t valid;
  int32_t pf;       /* brought in by the prefetcher, not yet used */
} axis_simt_way;

typedef struct {
  uint64_t key, last;  /* (warp, pc); the first line of its last request */
  int64_t stride;
  int32_t conf;
} axis_simt_pf_entry;

struct axis_simt_machine {
  const axis_simt_core *core;
  axis_simt_hooks hooks;
  const axis_lift_pack *L;
  const axis_exec_pack *E;
  int32_t slots, nstate;
  int32_t st_pred, st_arg, st_arg2, st_token, st_lane, st_lanes;
  uint32_t warps, lanes;
  uint64_t full_mask;
  axis_simt_warp warp[AXIS_SIMT_MAX_WARPS];
  uint64_t *regs;     /* [warp][lane][slot] */
  uint64_t *state;    /* [warp][lane][nstate] */
  axis_pack_state_entry *entries; /* scratch, nstate */
  uint64_t unit_free[AXIS_SIMT_MAX_UNITS][AXIS_SIMT_MAX_COPIES];
  uint64_t unit_slots[AXIS_SIMT_MAX_UNITS][AXIS_SIMT_MAX_COPIES];  /* in-flight cap: when each slot frees */
  uint32_t bar_count[AXIS_SIMT_MAX_BARRIERS];
  axis_simt_way *cache;
  axis_simt_way *l2;
  uint32_t l2_sets;
  axis_simt_pf_entry *pf;
  /* best-offset prefetcher */
  uint64_t *bop_line, *bop_ready;   /* recent-requests table, direct mapped */
  uint32_t bop_score[64];
  uint32_t bop_test, bop_round;
  int32_t bop_offset;               /* 0: prefetching off */
  uint32_t sets, ways;
  uint64_t lru_clock;
  uint64_t dram_free;                 /* when memory can start the next line */
  uint64_t mshr_free[256];            /* when each miss slot frees */
  axis_simt_decoded *decoded;  /* AXIS_SIMT_DECODE_CACHE, by word */
  uint64_t now;
  uint32_t last_warp;
  uint64_t done_at;
  char error[256];
  /* scratch for one instruction's memory accesses, lane by lane */
  uint64_t acc_addr[AXIS_SIMT_MAX_LINES];
  uint32_t acc_n;
  int32_t acc_write;
  uint64_t xlane[AXIS_SIMT_XLANE_REGIONS][AXIS_SIMT_MAX_LANES];
  uint8_t *bimodal;   /* out of order: two-bit counters by pc */
  uint8_t *divpred;   /* out of order: two-bit counters by pc -- will this branch split the warp? */
  uint32_t cur_warp, cur_lane;  /* whose instruction is executing */
  int32_t lane_fault;           /* the executing lane's access faulted */
  uint64_t fault_addr;
  struct { uint32_t w, l; uint64_t pc, addr; } faultq[AXIS_SIMT_MAX_LANES * 4];
  uint32_t fault_head, fault_n;
  int32_t foreseen_split;       /* the divergence predictor called this split: no redirect */
  /* U2: the described memory system this core is a port of, if any. Then
     there is no private cache, and every line goes through it, timed. */
  axis_ms *ms;
  int32_t ms_port, ms_system;
  axis_ms_stats ms_done[2];  /* the port's and the level below's, from systems a flush replaced */
  axis_simt_counters counters;
};

/* ---- small helpers ------------------------------------------------------- */

static uint64_t *axis_simt_lane_regs(axis_simt_machine *m, uint32_t w, uint32_t l) {
  return m->regs + ((size_t)w * m->lanes + l) * (size_t)m->slots;
}
static uint64_t *axis_simt_lane_state(axis_simt_machine *m, uint32_t w, uint32_t l) {
  return m->state + ((size_t)w * m->lanes + l) * (size_t)m->nstate;
}
static int axis_simt_state_slot(const axis_exec_pack *E, const char *name) {
  for (int32_t s = 0; s < E->state_slots(); ++s)
    if (!strcmp(E->state_name(s), name)) return s;
  return -1;
}
static uint32_t axis_simt_popcount(uint64_t x) { uint32_t n = 0; while (x) { x &= x - 1; ++n; } return n; }
static int axis_simt_first_lane(uint64_t mask) { for (int i = 0; i < 64; ++i) if (mask >> i & 1) return i; return -1; }
static int axis_simt_last_lane(uint64_t mask) { int l = -1; for (int i = 0; i < 64; ++i) if (mask >> i & 1) l = i; return l; }
static int axis_simt_fail(axis_simt_machine *m, const char *why, uint32_t w) {
  snprintf(m->error, sizeof m->error, "%s (warp %u, pc 0x%llx, cycle %llu)", why, w,
           (unsigned long long)m->warp[w].pc, (unsigned long long)m->now);
  return -1;
}

/* ---- memory: the host's, recorded on the way through --------------------- */

/* Where an address lives in the cache's eyes: inside the interleaved region,
   slot k's granule j sits at j * (threads * granule) + k * granule. Timing
   only -- the host's memory is addressed as the program addressed it. */
static uint64_t axis_simt_placed(const axis_simt_machine *m, uint64_t addr) {
  const axis_simt_core *c = m->core;
  if (!c->il_bytes) return addr;
  uint64_t threads = (uint64_t)m->warps * m->lanes;
  uint64_t lo = c->il_top - threads * c->il_bytes;
  if (addr < lo || addr >= c->il_top) return addr;
  uint64_t off = addr - lo, slot = off / c->il_bytes, in = off % c->il_bytes;
  if (!c->il_group)
    return lo + (in / c->il_granule) * threads * c->il_granule + slot * c->il_granule + in % c->il_granule;
  /* Within each group of il_group slots, optionally XOR-swizzled by group. */
  uint64_t g = c->il_group, member = slot % g, group = slot / g;
  uint64_t words = c->il_bytes / c->il_granule;
  uint64_t word = (in / c->il_granule) ^ (c->il_xor ? group % words : 0);
  return lo + ((group * words + word) * g + member) * c->il_granule + in % c->il_granule;
}

static uint64_t axis_simt_mem_read(void *ctx, uint64_t addr, uint32_t width) {
  axis_simt_machine *m = (axis_simt_machine *)ctx;
  if (addr >= AXIS_SIMT_XLANE_BASE) {  /* another lane's slice: not memory */
    uint64_t r = (addr - AXIS_SIMT_XLANE_BASE) >> 16, off = (addr - AXIS_SIMT_XLANE_BASE) & 0xffff, v = 0;
    if (r < AXIS_SIMT_XLANE_REGIONS && off + width / 8 <= (uint64_t)m->lanes * 8)
      memcpy(&v, (const uint8_t *)m->xlane[r] + off, width / 8);
    return v;
  }
  if (m->hooks.fault && (m->lane_fault || m->hooks.fault(m->hooks.ctx, m->cur_warp, m->cur_lane, addr, 0))) {
    if (!m->lane_fault) m->fault_addr = addr;
    m->lane_fault = 1;
    return 0;
  }
  if (m->acc_n < AXIS_SIMT_MAX_LINES) m->acc_addr[m->acc_n++] = axis_simt_placed(m, addr);
  return m->hooks.read(m->hooks.ctx, addr, width);
}
static void axis_simt_mem_write(void *ctx, uint64_t addr, uint64_t value, uint32_t width) {
  axis_simt_machine *m = (axis_simt_machine *)ctx;
  if (m->hooks.fault && (m->lane_fault || m->hooks.fault(m->hooks.ctx, m->cur_warp, m->cur_lane, addr, 1))) {
    /* ⚠️ An instruction's earlier writes have happened (a pair whose second
       half faults): only a page boundary inside one access does that. */
    if (!m->lane_fault) m->fault_addr = addr;
    m->lane_fault = 1;
    return;
  }
  if (m->acc_n < AXIS_SIMT_MAX_LINES) m->acc_addr[m->acc_n++] = axis_simt_placed(m, addr);
  m->acc_write = 1;
  if (m->core->excl_valid >= 0) {
    /* The write takes every OTHER thread's reservation that overlaps it. */
    const axis_simt_core *c = m->core;
    for (uint32_t w = 0; w < m->warps; ++w)
      for (uint32_t l = 0; l < m->lanes; ++l) {
        if (w == m->cur_warp && l == m->cur_lane) continue;
        uint64_t *st = axis_simt_lane_state(m, w, l);
        if (!(st[c->excl_valid] & 1)) continue;
        uint64_t lo = st[c->excl_address], hi = lo + (st[c->excl_size] & 0xff);
        if (addr < hi && lo < addr + width / 8) { st[c->excl_valid] = 0; ++m->counters.reservations_lost; }
      }
  }
  m->hooks.write(m->hooks.ctx, addr, value, width);
}

/* A miss, from `at`: wait for a miss slot, and for memory to be free if it
   goes there, then `latency`. Returns the cycle the line is back. */
static uint64_t axis_simt_miss(axis_simt_machine *m, uint64_t at, uint32_t latency, int memory) {
  const axis_simt_core *c = m->core;
  uint64_t start = at;
  int slot = -1;
  uint32_t n = c->cache_mshrs > 256 ? 256 : c->cache_mshrs;
  if (n) {
    slot = 0;
    for (uint32_t i = 1; i < n; ++i) if (m->mshr_free[i] < m->mshr_free[slot]) slot = (int)i;
    if (m->mshr_free[slot] > start) start = m->mshr_free[slot];
  }
  if (memory && c->cache_fill) {
    if (m->dram_free > start) start = m->dram_free;
    m->dram_free = start + c->cache_fill;
  }
  uint64_t back = start + latency;
  if (slot >= 0) m->mshr_free[slot] = back;
  return back;
}

/* Look a line up in one level: its way, or NULL. Touches its LRU. */
static axis_simt_way *axis_simt_find(axis_simt_machine *m, axis_simt_way *rows, uint32_t sets, uint32_t ways,
                                     uint64_t line) {
  axis_simt_way *row = rows + (size_t)(line % sets) * ways;
  for (uint32_t i = 0; i < ways; ++i)
    if (row[i].valid && row[i].tag == line) { row[i].lru = ++m->lru_clock; return &row[i]; }
  return NULL;
}
/* Allocate a line in one level (LRU victim). */
static axis_simt_way *axis_simt_place(axis_simt_machine *m, axis_simt_way *rows, uint32_t sets, uint32_t ways,
                                      uint64_t line) {
  axis_simt_way *row = rows + (size_t)(line % sets) * ways;
  uint32_t victim = 0;
  for (uint32_t i = 1; i < ways; ++i)
    if (!row[i].valid || (row[victim].valid && row[i].lru < row[victim].lru)) victim = i;
  axis_simt_way *v = &row[victim];
  memset(v, 0, sizeof *v);
  v->valid = 1; v->tag = line; v->lru = ++m->lru_clock;
  return v;
}

/* ---- the best-offset prefetcher (Michaud, HPCA 2016) ------------------------ */

/* Candidate offsets: 1..64 whose prime factors are at most 5, as in the paper. */
static const int32_t axis_simt_bop_offsets[] = { 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 15, 16, 18, 20, 24, 25,
                                                27, 30, 32, 36, 40, 45, 48, 50, 54, 60, 64 };
#define AXIS_SIMT_BOP_N ((uint32_t)(sizeof axis_simt_bop_offsets / sizeof axis_simt_bop_offsets[0]))
#define AXIS_SIMT_BOP_SCORE_MAX 31u
#define AXIS_SIMT_BOP_ROUND_MAX 100u
#define AXIS_SIMT_BOP_BAD_SCORE 1u

static uint32_t axis_simt_bop_slot(const axis_simt_machine *m, uint64_t line) {
  uint64_t h = line * 0x9e3779b97f4a7c15ull;
  return (uint32_t)((h ^ (h >> 31)) & (m->core->pf_entries - 1));
}
/* A line arrives (at `ready`): remember its base -- the line whose access
   would have asked for it -- so offsets are judged by whether they were in time. */
static void axis_simt_bop_record(axis_simt_machine *m, uint64_t base, uint64_t ready) {
  uint32_t s = axis_simt_bop_slot(m, base);
  m->bop_line[s] = base + 1;  /* +1: zero means empty */
  m->bop_ready[s] = ready;
}
/* Learn: at an access to `line`, test the next candidate offset. */
static void axis_simt_bop_learn(axis_simt_machine *m, uint64_t line) {
  int32_t d = axis_simt_bop_offsets[m->bop_test];
  if (line > (uint64_t)d) {
    uint64_t base = line - (uint64_t)d;
    uint32_t s = axis_simt_bop_slot(m, base);
    if (m->bop_line[s] == base + 1 && m->bop_ready[s] <= m->now) ++m->bop_score[m->bop_test];
  }
  uint32_t best = 0;
  for (uint32_t i = 1; i < AXIS_SIMT_BOP_N; ++i) if (m->bop_score[i] > m->bop_score[best]) best = i;
  int end = m->bop_score[best] >= AXIS_SIMT_BOP_SCORE_MAX;
  if (++m->bop_test == AXIS_SIMT_BOP_N) { m->bop_test = 0; end |= ++m->bop_round >= AXIS_SIMT_BOP_ROUND_MAX; }
  if (!end) return;
  /* A phase ends: the best offset, or none if even it scored too little. */
  m->bop_offset = m->bop_score[best] > AXIS_SIMT_BOP_BAD_SCORE ? axis_simt_bop_offsets[best] : 0;
  m->counters.bop_offset = (uint64_t)m->bop_offset;
  ++m->counters.bop_rounds;
  memset(m->bop_score, 0, sizeof m->bop_score);
  m->bop_round = 0;
  m->bop_test = 0;
}

static uint64_t axis_simt_touch_pf(axis_simt_machine *m, uint64_t line, uint64_t at, int prefetch);

/* A trigger -- a demand miss, or the first use of a prefetched line -- at `line`. */
static void axis_simt_bop_trigger(axis_simt_machine *m, uint64_t line, uint64_t at) {
  const axis_simt_core *c = m->core;
  axis_simt_bop_learn(m, line);
  if (!m->bop_offset) return;
  for (uint32_t k = 0; k < c->pf_degree; ++k) {
    uint64_t pl = line + (uint64_t)m->bop_offset + k;
    axis_simt_way *row = m->cache + (size_t)(pl % m->sets) * m->ways;
    int there = 0;
    for (uint32_t i = 0; i < m->ways; ++i) there |= row[i].valid && row[i].tag == pl;
    if (there) continue;
    uint64_t back = axis_simt_touch_pf(m, pl, at, 1) + m->now;
    axis_simt_bop_record(m, pl - (uint64_t)m->bop_offset, back);
    ++m->counters.prefetches;
  }
}

/* A line through the caches, requested at cycle `at`: how long from now until
   it is there. LRU, write-allocate. A prefetch counts nothing a demand
   access counts and marks the line it brings. */
static uint64_t axis_simt_touch_pf(axis_simt_machine *m, uint64_t line, uint64_t at, int prefetch) {
  const axis_simt_core *c = m->core;
  if (!m->cache) { ++m->counters.cache_misses; return axis_simt_miss(m, at, c->cache_miss, 1) - m->now; }
  axis_simt_way *w = axis_simt_find(m, m->cache, m->sets, m->ways, line);
  if (w) {
    uint64_t t = at + c->cache_hit;
    if (prefetch) return 0;
    ++m->counters.cache_hits;
    if (w->pf) {
      w->pf = 0;
      ++m->counters.prefetch_useful;
      if (m->bop_line) axis_simt_bop_trigger(m, line, at);
    }
    if (c->track_fills && w->ready > t) { t = w->ready; ++m->counters.fill_waits; }
    return t - m->now;
  }
  uint64_t back;
  if (m->l2) {
    axis_simt_way *w2 = axis_simt_find(m, m->l2, m->l2_sets, c->l2_ways, line);
    if (w2) {
      if (!prefetch) ++m->counters.l2_hits;
      back = axis_simt_miss(m, at, c->l2_hit, 0);
      if (c->track_fills && w2->ready > back) back = w2->ready;
    } else {
      if (!prefetch) ++m->counters.l2_misses;
      back = axis_simt_miss(m, at, c->cache_miss, 1);
      axis_simt_place(m, m->l2, m->l2_sets, c->l2_ways, line)->ready = back;
    }
  } else {
    back = axis_simt_miss(m, at, c->cache_miss, 1);
  }
  if (!prefetch) ++m->counters.cache_misses;
  axis_simt_way *v = axis_simt_place(m, m->cache, m->sets, m->ways, line);
  v->ready = back;
  v->pf = prefetch;
  if (!prefetch && m->bop_line) {
    /* With prefetching off, a demand fill is recorded as itself, so the
       learning phase can still find an offset and turn it back on. */
    if (!m->bop_offset) axis_simt_bop_record(m, line, back);
    axis_simt_bop_trigger(m, line, at);
  }
  if (!prefetch && c->pf_next_line)
    /* Next-line: a demand miss fetches the lines after it. */
    for (uint32_t k = 1; k <= c->pf_degree; ++k) {
      uint64_t pl = line + k;
      axis_simt_way *row = m->cache + (size_t)(pl % m->sets) * m->ways;
      int there = 0;
      for (uint32_t i = 0; i < m->ways; ++i) there |= row[i].valid && row[i].tag == pl;
      if (there) continue;
      axis_simt_touch_pf(m, pl, at, 1);
      ++m->counters.prefetches;
    }
  return back - m->now;
}
static uint64_t axis_simt_touch(axis_simt_machine *m, uint64_t line, uint64_t at) {
  return axis_simt_touch_pf(m, line, at, 0);
}

/* The stride prefetcher: per (warp, pc), once a load's first line has moved
   by the same stride twice running, fetch the lines its next `degree`
   requests will touch. */
static void axis_simt_prefetch(axis_simt_machine *m, uint64_t key, const uint64_t *lines, uint32_t n) {
  const axis_simt_core *c = m->core;
  if (!c->pf_degree || !n || !m->pf) return;
  /* Mix every bit of the key into the slot: the warp sits in its top bits,
     and a plain multiply-and-shift dropped it, so every warp's entry for one
     load shared a slot and reset the others' training. */
  uint64_t h = key * 0x9e3779b97f4a7c15ull;
  h ^= h >> 29;
  axis_simt_pf_entry *e = &m->pf[(h * 0xbf58476d1ce4e5b9ull >> 32) & (c->pf_entries - 1)];
  if (e->key != key) { e->key = key; e->last = lines[0]; e->stride = 0; e->conf = 0; return; }
  int64_t d = (int64_t)(lines[0] - e->last);
  if (d && d == e->stride) { if (e->conf < 3) ++e->conf; } else { e->stride = d; e->conf = 0; }
  e->last = lines[0];
  if (e->conf < 1 || !e->stride) return;
  uint32_t issued = 0;
  for (uint32_t k = 1; k <= c->pf_degree; ++k)
    for (uint32_t j = 0; j < n && issued < 64; ++j) {
      uint64_t pl = lines[j] + (uint64_t)(e->stride * (int64_t)k);
      axis_simt_way *row = m->cache + (size_t)(pl % m->sets) * m->ways;
      int there = 0;
      for (uint32_t i = 0; i < m->ways; ++i) there |= row[i].valid && row[i].tag == pl;
      if (there) continue;
      axis_simt_touch_pf(m, pl, m->now, 1);
      ++m->counters.prefetches;
      ++issued;
    }
}

/* ---- decode: once per word ------------------------------------------------ */

static int axis_simt_role_of(const axis_simt_core *c, const char *mnemonic) {
  for (int32_t r = 0; r < c->role_count; ++r)
    if (!strcmp(c->roles[r].mnemonic, mnemonic)) return c->roles[r].role;
  if (c->sysread_mnemonic && !strcmp(c->sysread_mnemonic, mnemonic)) return AXIS_SIMT_ROLE_SYSREAD;
  return AXIS_SIMT_ROLE_NONE;
}

static int axis_simt_unit_of(const axis_simt_core *c, const char *unit) {
  for (int32_t u = 0; u < c->unit_count; ++u)
    if (!strcmp(c->units[u].name, unit)) return u;
  return -1;
}

static const axis_simt_op *axis_simt_op_of(const char *isa, const char *mnemonic) {
  for (const axis_simt_op *o = AXIS_SIMT_OPS; o->mnemonic; ++o)
    if (!strcmp(o->mnemonic, mnemonic) && (!isa || !strcmp(o->isa, isa))) return o;
  return NULL;
}

/* The register an operand names, or -1: an immediate, or the zero register. */
static int32_t axis_simt_operand_slot(const axis_lift_pack *L, const axis_pack_lifted *lf, int32_t o) {
  const char *kind = L->operand_kind(lf->index, o);
  if (!kind || !strcmp(kind, "imm") || !lf->operand_valid[o]) return -1;
  for (const axis_simt_class *k = AXIS_SIMT_CLASSES; k->name; ++k)
    if (!strcmp(k->name, kind)) {
      if (k->zero_index >= 0 && lf->operands[o] == (uint32_t)k->zero_index) return -1;
      return (int32_t)L->register_slot(lf->index, o, lf->operands[o]);
    }
  return -1;  /* not a register class: an immediate by another name */
}

static void axis_simt_add(int32_t *list, int32_t *n, int32_t v) {
  for (int32_t i = 0; i < *n; ++i) if (list[i] == v) return;
  if (*n < AXIS_SIMT_MAX_DEPS) list[(*n)++] = v;
}

static const axis_simt_decoded *axis_simt_decode(axis_simt_machine *m, uint32_t word) {
  axis_simt_decoded *d = &m->decoded[(word * 2654435761u) % AXIS_SIMT_DECODE_CACHE];
  if (d->valid && d->word == word) return d;
  memset(d, 0, sizeof *d);
  d->word = word;
  d->index = -1;
  const axis_simt_core *c = m->core;
  for (int32_t i = 0; i < c->isa_count; ++i) {
    axis_pack_lifted lf;
    if (m->L->lift(word, c->isas[i], &lf) && lf.index >= 0) { d->lifted = lf; d->index = lf.index; d->isa = c->isas[i]; break; }
  }
  d->valid = 1;
  if (d->index < 0) return d;
  const char *mn = m->L->mnemonic(d->index);
  d->op = axis_simt_op_of(d->isa, mn);
  d->role = axis_simt_role_of(c, mn);
  {
    size_t best = 0;  /* the longest matching prefix */
    for (int32_t k = 0; k < c->lat_count; ++k) {
      size_t n = strlen(c->lat_prefix[k]);
      if (n > best && !strncmp(mn, c->lat_prefix[k], n)) { best = n; d->latency = c->lat_cycles[k]; }
    }
  }
  d->unit = d->op ? axis_simt_unit_of(c, d->op->unit) : -1;
  for (int32_t o = 0; o < d->lifted.operand_count; ++o) {
    int32_t slot = axis_simt_operand_slot(m->L, &d->lifted, o);
    if (slot < 0) continue;
    const char *role = m->L->operand_role(d->index, o);
    if (!strcmp(role, "in") || !strcmp(role, "inout")) axis_simt_add(d->src, &d->nsrc, slot);
    if (!strcmp(role, "out") || !strcmp(role, "inout")) axis_simt_add(d->dst, &d->ndst, slot);
    if (c->vec_isa) {
      const char *kind = m->L->operand_kind(d->index, o);
      int lane_class = 0;
      for (const char *const *k = c->vec_classes; *k; ++k) lane_class |= !strcmp(*k, kind);
      if (lane_class) {
        for (int32_t i = 0; i < d->nsrc; ++i) if (d->src[i] == slot) d->src_lane |= 1u << i;
        for (int32_t i = 0; i < d->ndst; ++i) if (d->dst[i] == slot) d->dst_lane |= 1u << i;
      }
      if (m->L->operand_width(d->index, o) > 64) d->wide = 1;
    }
  }
  if (c->imp_policy) {
    for (const char *const *b = c->imp_calls; *b; ++b) d->call |= !strcmp(*b, mn);
    for (const char *const *b = c->imp_rets; *b; ++b) d->ret |= !strcmp(*b, mn);
    for (const char *const *b = c->imp_yields; *b; ++b) d->yield |= !strcmp(*b, mn);
    for (const char *const *b = c->imp_relax; *b; ++b) d->relax |= !strcmp(*b, mn);
    for (const char *const *b = c->imp_wait; *b; ++b) d->wfe |= !strcmp(*b, mn);
    for (const char *const *b = c->imp_send; *b; ++b) d->sev |= !strcmp(*b, mn);
    for (const char *const *b = c->imp_send_local; *b; ++b) d->sevl |= !strcmp(*b, mn);
  }
  if (c->vec_isa) {
    d->vec = !strcmp(d->isa, c->vec_isa);
    for (const char *const *b = c->vec_bcast; *b; ++b) d->bcast |= !strcmp(*b, mn);
    for (const char *const *b = c->vec_flags; *b; ++b) d->pflags |= !strcmp(*b, mn);
    for (const char *const *b = c->vec_xlane; *b; ++b) d->xlane |= !strcmp(*b, mn);
    for (const char *const *b = c->vec_sum; *b; ++b) d->sum |= !strcmp(*b, mn);
    if (d->pflags && c->vec_flag_state >= 0) axis_simt_add(d->dst, &d->ndst, 1000 + c->vec_flag_state);
  }
  if (d->op) {
    /* The engine's own scratch (simt_*) is read only by the warp logic, and
       the description's untracked state is sticky: neither is a dependence. */
    uint64_t untracked = c->untracked;
    if (m->st_pred >= 0) untracked |= 1ull << m->st_pred;
    if (m->st_arg >= 0) untracked |= 1ull << m->st_arg;
    if (m->st_arg2 >= 0) untracked |= 1ull << m->st_arg2;
    if (m->st_token >= 0) untracked |= 1ull << m->st_token;
    if (m->st_lane >= 0) untracked |= 1ull << m->st_lane;
    if (m->st_lanes >= 0) untracked |= 1ull << m->st_lanes;
    for (int32_t s = 0; s < m->nstate && s < 64; ++s) {
      if (untracked >> s & 1) continue;
      if (d->op->state_reads >> s & 1) axis_simt_add(d->src, &d->nsrc, 1000 + s);
      if (d->op->state_writes >> s & 1) axis_simt_add(d->dst, &d->ndst, 1000 + s);
    }
    for (int32_t k = 0; k < 4; ++k) {
      if (d->op->fixed_reads[k] >= 0) axis_simt_add(d->src, &d->nsrc, d->op->fixed_reads[k]);
      if (d->op->fixed_writes[k] >= 0) axis_simt_add(d->dst, &d->ndst, d->op->fixed_writes[k]);
    }
  }
  if (d->role == AXIS_SIMT_ROLE_SYSREAD) {
    d->sys_dst_slot = -1;
    for (int32_t o = 0; o < d->lifted.operand_count; ++o) {
      const char *name = m->L->operand_name(d->index, o);
      if (!strcmp(name, c->sysread_dst)) {
        d->sys_dst_slot = axis_simt_operand_slot(m->L, &d->lifted, o);
        if (d->sys_dst_slot >= 0) axis_simt_add(d->dst, &d->ndst, d->sys_dst_slot);
      }
      for (int32_t t = 0; t < c->sysread_terms; ++t)
        if (!strcmp(name, c->sysread_operand[t])) d->sys_index += d->lifted.operands[o] * c->sysread_weight[t];
    }
  }
  return d;
}

/* ---- the machine ---------------------------------------------------------- */

static const axis_simt_core *axis_simt_find_core(const char *name) {
  for (const axis_simt_core *c = AXIS_SIMT_CORES; c->name; ++c)
    if (!strcmp(c->name, name)) return c;
  return NULL;
}

axis_simt_machine *axis_simt_create(const char *core, const axis_simt_hooks *hooks, char *err, size_t err_size) {
  const axis_simt_core *c = axis_simt_find_core(core);
  if (!c) { if (err) snprintf(err, err_size, "no SIMT core `%s` in this description", core); return NULL; }
  axis_simt_machine *m = (axis_simt_machine *)calloc(1, sizeof *m);
  m->core = c;
  m->hooks = *hooks;
  m->L = axis_simt_L();
  m->E = axis_simt_E();
  m->slots = m->E->register_slots();
  m->nstate = m->E->state_slots();
  /* ⚠️ The timing rows' state masks were written in the order the emitter
     saw the state; refuse a pack that lists it in another, rather than read
     one slot's dependence as another's. */
  for (int32_t s = 0; s < m->nstate || AXIS_SIMT_STATE[s]; ++s) {
    if (s >= m->nstate || !AXIS_SIMT_STATE[s] || strcmp(AXIS_SIMT_STATE[s], m->E->state_name(s))) {
      if (err) snprintf(err, err_size, "the exec pack's state slot %d is not the one this engine was generated for", (int)s);
      free(m);
      return NULL;
    }
  }
  if (m->nstate > 64) {
    if (err) snprintf(err, err_size, "%d state slots; the engine's masks hold 64", (int)m->nstate);
    free(m);
    return NULL;
  }
  m->warps = c->warps;
  m->lanes = c->lanes;
  m->full_mask = c->lanes >= 64 ? ~0ull : ((1ull << c->lanes) - 1);
  m->st_pred = axis_simt_state_slot(m->E, "simt_pred");
  m->st_arg = axis_simt_state_slot(m->E, "simt_arg");
  m->st_arg2 = axis_simt_state_slot(m->E, "simt_arg2");
  m->st_token = axis_simt_state_slot(m->E, "simt_token");
  m->st_lane = axis_simt_state_slot(m->E, "simt_lane");
  m->st_lanes = axis_simt_state_slot(m->E, "simt_lanes");
  m->regs = (uint64_t *)calloc((size_t)c->warps * c->lanes * (size_t)m->slots, sizeof(uint64_t));
  m->state = (uint64_t *)calloc((size_t)c->warps * c->lanes * (size_t)(m->nstate ? m->nstate : 1), sizeof(uint64_t));
  m->entries = (axis_pack_state_entry *)calloc((size_t)(m->nstate ? m->nstate : 1), sizeof *m->entries);
  for (int32_t s = 0; s < m->nstate; ++s) { m->entries[s].name = m->E->state_name(s); m->entries[s].width = m->E->state_width(s); }
  for (uint32_t w = 0; w < c->warps; ++w) m->warp[w].reg_ready = (uint64_t *)calloc((size_t)m->slots, sizeof(uint64_t));
  if (c->ooo_rob)
    for (uint32_t w = 0; w < c->warps; ++w) {
      m->warp[w].rob = (axis_simt_uop *)calloc(c->ooo_rob, sizeof(axis_simt_uop));
      m->warp[w].reg_writer = (uint64_t *)calloc((size_t)m->slots, sizeof(uint64_t));
      if (c->imp_smt) {
        m->warp[w].lreg_writer = (uint64_t *)calloc((size_t)m->slots * c->lanes, sizeof(uint64_t));
        m->warp[w].lstate_writer = (uint64_t *)calloc((size_t)64 * c->lanes, sizeof(uint64_t));
      }
      if (c->ooo_memorder) {
        m->warp[w].store_at = (uint64_t *)calloc(AXIS_SIMT_STORE_TABLE, sizeof(uint64_t));
        m->warp[w].store_seq = (uint64_t *)calloc(AXIS_SIMT_STORE_TABLE, sizeof(uint64_t));
      }
    }
  if (c->ooo_predict == 2) m->bimodal = (uint8_t *)calloc(c->ooo_entries, 1);
  if (c->ooo_divergence) m->divpred = (uint8_t *)calloc(c->ooo_entries, 1);
  if (c->cache_bytes) {
    m->ways = c->cache_ways;
    m->sets = c->cache_bytes / (c->line * c->cache_ways);
    m->cache = (axis_simt_way *)calloc((size_t)m->sets * m->ways, sizeof(axis_simt_way));
    if (c->l2_bytes) {
      m->l2_sets = c->l2_bytes / (c->line * c->l2_ways);
      m->l2 = (axis_simt_way *)calloc((size_t)m->l2_sets * c->l2_ways, sizeof(axis_simt_way));
    }
    if (c->pf_degree && !c->pf_next_line && !c->pf_best_offset)
      m->pf = (axis_simt_pf_entry *)calloc(c->pf_entries, sizeof(axis_simt_pf_entry));
    if (c->pf_degree && c->pf_best_offset) {
      m->bop_line = (uint64_t *)calloc(c->pf_entries, sizeof(uint64_t));
      m->bop_ready = (uint64_t *)calloc(c->pf_entries, sizeof(uint64_t));
      m->bop_offset = 1;  /* start as next-line until a phase decides */
      m->counters.bop_offset = 1;
    }
  }
  m->decoded = (axis_simt_decoded *)calloc(AXIS_SIMT_DECODE_CACHE, sizeof(axis_simt_decoded));
  /* U2: a port of a described memory system. */
  for (int32_t k = 0; k < AXIS_MS_SYSTEM_COUNT; ++k) {
    if (!AXIS_MS_SYSTEMS[k].node_count) continue;
    axis_ms *ms = axis_ms_new(&AXIS_MS_SYSTEMS[k]);
    int32_t port = ms ? axis_ms_port(ms, c->name) : -1;
    if (port >= 0) { m->ms = ms; m->ms_port = port; m->ms_system = k; break; }
    axis_ms_free(ms);
  }
  return m;
}

void axis_simt_destroy(axis_simt_machine *m) {
  if (!m) return;
  for (uint32_t w = 0; w < m->warps; ++w) { free(m->warp[w].reg_ready); free(m->warp[w].rob); free(m->warp[w].reg_writer); free(m->warp[w].lreg_writer); free(m->warp[w].lstate_writer); free(m->warp[w].store_at); free(m->warp[w].store_seq); }
  free(m->bimodal);
  free(m->divpred);
  free(m->regs); free(m->state); free(m->entries); free(m->cache); free(m->l2); free(m->pf); free(m->bop_line); free(m->bop_ready); free(m->decoded);
  if (m->ms) axis_ms_free(m->ms);
  free(m);
}

/* Empty the data cache: what a host does when it has written memory the
   cache holds. Timing only -- lanes always read memory itself. */
void axis_simt_flush_cache(axis_simt_machine *m) {
  if (m->cache) memset(m->cache, 0, (size_t)m->sets * m->ways * sizeof(axis_simt_way));
  if (m->l2) memset(m->l2, 0, (size_t)m->l2_sets * m->core->l2_ways * sizeof(axis_simt_way));
  if (m->pf) memset(m->pf, 0, (size_t)m->core->pf_entries * sizeof(axis_simt_pf_entry));
  if (m->bop_line) {
    memset(m->bop_line, 0, (size_t)m->core->pf_entries * sizeof(uint64_t));
    memset(m->bop_ready, 0, (size_t)m->core->pf_entries * sizeof(uint64_t));
  }
  memset(m->mshr_free, 0, sizeof m->mshr_free);
  m->dram_free = 0;
  if (m->ms && (m->ms_system < 0 || m->ms->refs > 1)) {
    /* Shared with another machine: its lines are that machine's too, and
       emptying them is not this core's to do. */
  } else if (m->ms) {
    /* A fresh system: what the host wrote is in memory, not in any level.
       Its counters carry over, as a private cache's do. */
    int32_t below = m->ms->cfg->nodes[m->ms_port].next;
    for (int32_t k = 0; k < 2; ++k) {
      int32_t node = k ? below : m->ms_port;
      if (node < 0) continue;
      const uint64_t *from = (const uint64_t *)axis_ms_stats_of(m->ms, node);
      uint64_t *to = (uint64_t *)&m->ms_done[k];
      for (size_t f = 0; f < sizeof(axis_ms_stats) / sizeof(uint64_t); ++f) to[f] += from[f];
    }
    axis_ms_free(m->ms);
    m->ms = axis_ms_new(&AXIS_MS_SYSTEMS[m->ms_system]);
  }
}

uint32_t axis_simt_warps(const axis_simt_machine *m) { return m->warps; }
/* A warp's thread mask and which warps are running: machine state a host's
   identity registers report (Vortex's ACTIVE_THREADS / ACTIVE_WARPS). */
uint64_t axis_simt_warp_mask(const axis_simt_machine *m, uint32_t w) { return w < m->warps ? m->warp[w].mask : 0; }
uint64_t axis_simt_active_warps(const axis_simt_machine *m) {
  uint64_t a = 0;
  for (uint32_t w = 0; w < m->warps; ++w) if (m->warp[w].active) a |= 1ull << w;
  return a;
}
uint32_t axis_simt_lanes(const axis_simt_machine *m) { return m->lanes; }
const char *axis_simt_error(const axis_simt_machine *m) { return m->error; }
const axis_simt_counters *axis_simt_stats(const axis_simt_machine *m) {
  if (m->ms) {
    /* A port's counters are its first level's, and the level below it is
       what the private cache called its L2. */
    axis_simt_machine *mm = (axis_simt_machine *)m;
    const axis_ms_stats *p = axis_ms_stats_of(m->ms, m->ms_port);
    const axis_ms_stats *d = &m->ms_done[0];
    mm->counters.cache_hits = p->hits + d->hits;
    mm->counters.cache_misses = p->misses + d->misses;
    mm->counters.prefetches = p->prefetches + d->prefetches;
    mm->counters.prefetch_useful = p->prefetch_useful + d->prefetch_useful;
    mm->counters.fill_waits = p->fill_waits + d->fill_waits;
    mm->counters.bop_offset = p->bop_offset;
    mm->counters.bop_rounds = p->bop_rounds + d->bop_rounds;
    int32_t below = m->ms->cfg->nodes[m->ms_port].next;
    if (below >= 0 && m->ms->cfg->nodes[below].kind == AXIS_MS_CACHE) {
      const axis_ms_stats *q = axis_ms_stats_of(m->ms, below);
      mm->counters.l2_hits = q->hits + m->ms_done[1].hits;
      mm->counters.l2_misses = q->misses + m->ms_done[1].misses;
    }
  }
  return &m->counters;
}

void axis_simt_set_reg(axis_simt_machine *m, uint32_t w, uint32_t l, int32_t slot, uint64_t v) {
  if (w < m->warps && l < m->lanes && slot >= 0 && slot < m->slots) axis_simt_lane_regs(m, w, l)[slot] = v;
}
uint64_t axis_simt_reg(axis_simt_machine *m, uint32_t w, uint32_t l, int32_t slot) {
  return (w < m->warps && l < m->lanes && slot >= 0 && slot < m->slots) ? axis_simt_lane_regs(m, w, l)[slot] : 0;
}
int axis_simt_set_state(axis_simt_machine *m, uint32_t w, uint32_t l, const char *name, uint64_t v) {
  int s = axis_simt_state_slot(m->E, name);
  if (s < 0 || w >= m->warps || l >= m->lanes) return 0;
  axis_simt_lane_state(m, w, l)[s] = v;
  return 1;
}

int axis_simt_set_vector(axis_simt_machine *m, uint32_t w, int on) {
  if (w >= m->warps || (on && !m->core->vec_isa)) return 0;
  m->warp[w].vector = on != 0;
  return 1;
}

uint64_t axis_simt_state(axis_simt_machine *m, uint32_t w, uint32_t l, const char *name) {
  int s = axis_simt_state_slot(m->E, name);
  return (s < 0 || w >= m->warps || l >= m->lanes) ? 0 : axis_simt_lane_state(m, w, l)[s];
}

/* Start (or restart) a warp: a pc and a mask. Its registers are whatever
   they hold -- set them first. Its reconvergence stack starts empty. */
void axis_simt_start_warp(axis_simt_machine *m, uint32_t w, uint64_t pc, uint64_t mask) {
  if (w >= m->warps) return;
  axis_simt_warp *wp = &m->warp[w];
  wp->active = 1;
  wp->pc = pc;
  wp->mask = mask & m->full_mask;
  wp->depth = 0;
  wp->npaths = 0;
  memset(wp->calldepth, 0, sizeof wp->calldepth);
  memset(wp->aside, 0, sizeof wp->aside);
  wp->stint = 0;
  wp->event = wp->asleep = 0;
  wp->dormant = 0;
  memset(wp->front_ready, 0, sizeof wp->front_ready);
  wp->waiting_bar = 0;
  wp->draining = 0;
  wp->started = m->now;
  /* A front end left waiting by the warp's last run waits on nothing now
     (with paths issuing as SMT threads, the wait it was in was a path's,
     and that path is gone). */
  if (wp->ready_at < m->now || wp->ready_at == UINT64_MAX) wp->ready_at = m->now;
}

static int axis_simt_ready(axis_simt_machine *m, axis_simt_warp *wp, const axis_simt_decoded *d) {
  if (m->core->ooo_rob) {
    /* Out of order, dispatch needs only a free entry: what the instruction
       waits for -- its sources, a unit -- it waits for in the window. */
    if (wp->rob_next - wp->rob_head >= m->core->ooo_rob) { ++m->counters.rob_full; return 0; }
    return 1;
  }
  for (int32_t i = 0; i < d->nsrc; ++i) {
    int32_t s = d->src[i];
    uint64_t r = s >= 1000 ? wp->state_ready[s - 1000] : wp->reg_ready[s];
    if (r > m->now) return 0;
  }
  for (int32_t i = 0; i < d->ndst; ++i) {
    int32_t s = d->dst[i];
    uint64_t r = s >= 1000 ? wp->state_ready[s - 1000] : wp->reg_ready[s];
    if (r > m->now) return 0;  /* WAW: in order, but a short op must not finish under a long one */
  }
  if (d->unit >= 0) {
    const axis_simt_unit *u = &m->core->units[d->unit];
    /* An in-flight cap does not hold the warp at issue: the operation
       queues at the unit and is admitted in arrival order (axis_simt_issue). */
    for (uint32_t k = 0; k < u->count && k < AXIS_SIMT_MAX_COPIES; ++k)
      if (m->unit_free[d->unit][k] <= m->now) return 1;
    return 0;
  }
  return 1;
}

static void axis_simt_finish_warp(axis_simt_machine *m, uint32_t w) {
  axis_simt_warp *wp = &m->warp[w];
  wp->active = 0;
  if (wp->inflight_until > m->done_at) m->done_at = wp->inflight_until;
  ++m->counters.warps_retired;
  if (wp->spawn_pc) {
    /* It was spawned again while it retired: it starts now. */
    uint64_t pc = wp->spawn_pc;
    wp->spawn_pc = 0;
    axis_simt_start_warp(m, w, pc, 1);
    return;
  }
  if (m->hooks.warp_done) m->hooks.warp_done(m->hooks.ctx, m, w);  /* may restart it */
}

/* ---- charging an instruction that starts now ------------------------------- */

/* Its lines through the cache and a unit; returns when its result is ready. */
static uint64_t axis_simt_charge(axis_simt_machine *m, int32_t unit, uint32_t occupancy, uint32_t latency,
                                 uint32_t unit_latency, const uint64_t *lines, uint32_t n, uint64_t key, int write) {
  const axis_simt_core *c = m->core;
  const axis_simt_unit *u = unit >= 0 ? &c->units[unit] : NULL;
  uint64_t memory = 0, unit_wait = 0;
  if (n) {
    /* One line a cycle into each bank: lines in different banks go in
       together, lines sharing one queue behind each other. */
    uint32_t banks = c->cache_banks > 1 ? c->cache_banks : 1;
    uint32_t queued[64] = {0};
    for (uint32_t k = 0; k < n; ++k) {
      uint32_t b = (uint32_t)(lines[k] % banks);
      uint64_t at = m->now + queued[b]++;
      uint64_t t;
      if (m->ms) {
        /* The described memory system, timed: the request's first line trains
           a stride prefetcher keyed by (warp, pc), and every line may use it.
           ⚠️ An address outside the system's map costs a memory system
           nothing: refuse it rather than run on free memory (a description
           whose map missed the interleaved stacks did exactly that). */
        if (axis_ms_region(m->ms, lines[k] * c->line) < 0) {
          char why[160];
          snprintf(why, sizeof why, "line %#llx is outside memory system `%s`'s address map",
                   (unsigned long long)(lines[k] * c->line), m->ms->cfg->name);
          axis_simt_fail(m, why, m->cur_warp);
          return UINT64_MAX / 2;
        }
        t = axis_ms_access_at(m->ms, m->ms_port, lines[k] * c->line, write, at, key | 1, k == 0) - m->now;
      } else {
        t = axis_simt_touch(m, lines[k], at);
      }
      if (t > memory) memory = t;
    }
    if (!m->ms) axis_simt_prefetch(m, key, lines, n);
  }
  if (u) {
    uint32_t best = 0;
    for (uint32_t k = 1; k < u->count && k < AXIS_SIMT_MAX_COPIES; ++k)
      if (m->unit_free[unit][k] < m->unit_free[unit][best]) best = k;
    m->unit_free[unit][best] = m->now + (u->pipelined ? occupancy : (uint64_t)occupancy * latency);
    if (u->interval) {
      /* The in-flight cap: the operation waits at the unit for the slot that
         frees first and holds it for the unit's own latency. Issues are in
         time order, so taking the earliest slot is arrival order. Holding the
         warp at issue instead has the same ideal throughput and locks into
         slower phases (a dependent FP chain on 4 warps: 7.0 or 8.3 cycles an
         op by alignment; SimX, which queues, is 7.0 at every one). */
      uint32_t slot = 0;
      for (uint32_t k = 1; k < u->interval && k < AXIS_SIMT_MAX_COPIES; ++k)
        if (m->unit_slots[unit][k] < m->unit_slots[unit][slot]) slot = k;
      uint64_t admit = m->unit_slots[unit][slot] > m->now ? m->unit_slots[unit][slot] : m->now;
      unit_wait = admit - m->now;
      m->unit_slots[unit][slot] = admit + unit_latency;
    }
  }
  return m->now + unit_wait + (occupancy - 1) + latency + memory;
}

/* ---- out of order: the window ---------------------------------------------- */

/* One cycle of every warp's window: retire what is done, in order, and start
   every dispatched instruction whose producers are done and whose unit has a
   free copy, oldest first. Resources are taken in time order, as they are
   in order -- which is why an instruction is charged here, when it starts,
   and not when it was dispatched. */
static void axis_simt_window_tick(axis_simt_machine *m) {
  const axis_simt_core *c = m->core;
  uint32_t first = (uint32_t)(m->now % m->warps);  /* no warp is always first at a unit */
  for (uint32_t i = 0; i < m->warps; ++i) {
    axis_simt_warp *wp = &m->warp[(first + i) % m->warps];
    while (wp->rob_head < wp->rob_next) {
      axis_simt_uop *q = &wp->rob[wp->rob_head % c->ooo_rob];
      if (!q->issued || q->done > m->now) break;
      ++wp->rob_head;
    }
    for (uint64_t seq = wp->rob_head; seq < wp->rob_next; ++seq) {
      axis_simt_uop *q = &wp->rob[seq % c->ooo_rob];
      if (q->issued) continue;
      int ready = 1;
      for (int32_t k = 0; k < q->ndep && ready; ++k) {
        if (q->dep[k] < wp->rob_head) continue;  /* retired */
        const axis_simt_uop *p = &wp->rob[q->dep[k] % c->ooo_rob];
        ready = p->issued && p->done <= m->now;
      }
      if (ready && q->unit >= 0) {
        const axis_simt_unit *u = &c->units[q->unit];
        ready = 0;
        for (uint32_t k = 0; k < u->count && k < AXIS_SIMT_MAX_COPIES; ++k)
          ready |= m->unit_free[q->unit][k] <= m->now;
      }
      if (!ready) continue;
      q->done = axis_simt_charge(m, q->unit, q->occupancy, q->latency, q->unit_latency, q->lines, q->nlines, q->key, q->write);
      q->issued = 1;
      for (int32_t k = 0; k < q->ndst; ++k) {
        int32_t sl = q->dst[k];
        if (sl >= 1000) wp->state_ready[sl - 1000] = q->done; else wp->reg_ready[sl] = q->done;
      }
      if (q->done > wp->inflight_until) wp->inflight_until = q->done;
      if (q->done > m->done_at) m->done_at = q->done;
      if (q->front) {
        if (c->imp_smt) {
          for (uint32_t l = 0; l < m->lanes; ++l)
            if (q->lanes >> l & 1) wp->front_ready[l] = q->done + c->branch_penalty;
          if (wp->mask & q->lanes) wp->ready_at = q->done + c->branch_penalty;
        } else {
          wp->ready_at = q->done + c->branch_penalty;
        }
      }
    }
  }
}

/* ---- implicit divergence: paths ------------------------------------------- */

/* Park a path, or add its lanes to the parked path already at that pc. */
static int axis_simt_at_hint(axis_simt_machine *m, uint64_t pc);
/* Threads that meet at a reconvergence hint are at the same point of the
   program, whatever call depth each counted to get there -- threads an OS
   started enter a parallel region from different depths (the master from
   inside the program, workers from their idle loop). So where a hint merges
   paths, every lane takes the depth of the path that was already there, and
   call depth orders them as one thread from then on. */
static void axis_simt_meet(axis_simt_machine *m, axis_simt_warp *wp, uint64_t pc, uint64_t into, uint64_t joining) {
  if (m->core->imp_policy != 3 || !axis_simt_at_hint(m, pc)) return;
  int f = axis_simt_first_lane(into);
  if (f < 0) return;
  for (uint32_t l = 0; l < m->lanes; ++l)
    if (joining >> l & 1) wp->calldepth[l] = wp->calldepth[f];
}
/* Whether two paths may become one: lanes of one tag (address space), and
   both asleep or both awake -- a sleeper merged into a running path would
   run without its event. */
static int axis_simt_same_tag(const axis_simt_warp *wp, uint64_t a, uint64_t b) {
  int la = axis_simt_first_lane(a), lb = axis_simt_first_lane(b);
  return la < 0 || lb < 0 || (wp->tag[la] == wp->tag[lb] && (wp->asleep >> la & 1) == (wp->asleep >> lb & 1));
}
static void axis_simt_park(axis_simt_machine *m, axis_simt_warp *wp, uint64_t pc, uint64_t mask, int met) {
  for (uint32_t l = 0; l < m->lanes; ++l)
    if (mask >> l & 1) wp->parked_at[l] = m->now + 1;
  for (uint32_t k = 0; k < wp->npaths; ++k)
    if (wp->path_pc[k] == pc && axis_simt_same_tag(wp, wp->path_mask[k], mask)) {
      axis_simt_meet(m, wp, pc, wp->path_mask[k], mask);
      wp->path_mask[k] |= mask;
      m->counters.path_merges += (uint64_t)met;
      return;
    }
  wp->path_pc[wp->npaths] = pc;
  wp->path_mask[wp->npaths++] = mask;
  if (wp->npaths + 1 > m->counters.max_paths) m->counters.max_paths = wp->npaths + 1;
}

/* Whether the instruction at pc is a reconvergence hint. */
static int axis_simt_at_hint(axis_simt_machine *m, uint64_t pc) {
  if (!*m->core->imp_yields) return 0;
  int ok = 1;
  uint32_t word = m->hooks.fetch(m->hooks.ctx, pc, &ok);
  return ok && axis_simt_decode(m, word)->yield;
}

/* Whether path a should run before path b: the policy. Depth is read from the
   path's first lane -- lanes that share a pc at different depths (recursion)
   are one path all the same. */
/* (path-issue smt): when a path's front end may go on -- all its lanes'. */
static uint64_t axis_simt_path_ready(const axis_simt_machine *m, const axis_simt_warp *wp, uint64_t mask) {
  uint64_t r = 0;
  for (uint32_t l = 0; l < m->lanes; ++l)
    if ((mask >> l & 1) && wp->front_ready[l] > r) r = wp->front_ready[l];
  return r;
}

/* (path-issue smt N): whether the warp's front ends are all taken -- N of its
   paths (running or parked) wait on a branch -- so no further path may start. */
static int axis_simt_fronts_full(const axis_simt_machine *m, const axis_simt_warp *wp) {
  uint32_t cap = m->core->imp_smt_fronts, busy = 0;
  if (!cap) return 0;
  busy += axis_simt_path_ready(m, wp, wp->mask) > m->now;
  for (uint32_t k = 0; k < wp->npaths; ++k) busy += axis_simt_path_ready(m, wp, wp->path_mask[k]) > m->now;
  return busy >= cap;
}

static int axis_simt_path_before(axis_simt_machine *m, uint32_t w, uint64_t pc_a, uint64_t mask_a,
                                 uint64_t pc_b, uint64_t mask_b) {
  const axis_simt_core *c = m->core;
  axis_simt_warp *wp = &m->warp[w];
  int la = 0, lb = 0;
  while (!(mask_a >> la & 1)) ++la;
  while (!(mask_b >> lb & 1)) ++lb;
  /* A path asleep at a wait never runs before one that is awake. */
  int za = (int)(wp->asleep >> la & 1), zb = (int)(wp->asleep >> lb & 1);
  if (za != zb) return zb;
  /* A privileged path (tag bit 31: a thread taken into an exception
     handler) runs before the threads' own: it entered at no call depth and
     at a kernel address, so depth and pc alike would put it last, and the
     thread would fall behind its warp for as long as the others ran. */
  int pa = (int)(wp->tag[la] >> 31 & 1), pb = (int)(wp->tag[lb] >> 31 & 1);
  if (pa != pb) return pa;
  /* A path at a reconvergence hint waits for the ones that are not. */
  int ha = axis_simt_at_hint(m, pc_a), hb = axis_simt_at_hint(m, pc_b);
  /* A path set aside -- by (progress N), or a spin-loop hint -- is waiting
     too. Paths that are waiting, either way, run after every path that is
     not; among them, the one that has waited longest runs first, so that
     neither kind can hold the other off for ever: a spinner re-set aside at
     every trip grows younger, and a path at a hint grows older. (Two paths
     at hints with neither set aside: the policy, as before.) */
  uint64_t xa = wp->aside[la], xb = wp->aside[lb];
  if (xa || xb) {
    int wa = xa || ha, wb = xb || hb;
    if (wa != wb) return wb;
    int run_a = pc_a == wp->pc && mask_a == wp->mask, run_b = pc_b == wp->pc && mask_b == wp->mask;
    uint64_t sa = xa ? xa : run_a ? m->now + 1 : wp->parked_at[la];
    uint64_t sb = xb ? xb : run_b ? m->now + 1 : wp->parked_at[lb];
    if (sa != sb) return sa < sb;
  }
  if (ha != hb) return hb;
  /* Paths issuing as SMT threads: of two paths neither of which is waiting
     (set aside, or at a hint -- those go after, whatever their front ends),
     one whose front end can go on now runs before one waiting on its branch. */
  if (m->core->imp_smt && !axis_simt_fronts_full(m, wp)) {
    int ra = axis_simt_path_ready(m, wp, mask_a) <= m->now, rb = axis_simt_path_ready(m, wp, mask_b) <= m->now;
    if (ra != rb) return ra;
  }
  uint64_t da = 0, db = 0;
  if (c->imp_policy == 2 && c->imp_sp_state >= 0) {
    da = (0 - axis_simt_lane_state(m, w, (uint32_t)la)[c->imp_sp_state]) & (c->imp_stack - 1);
    db = (0 - axis_simt_lane_state(m, w, (uint32_t)lb)[c->imp_sp_state]) & (c->imp_stack - 1);
  } else if (c->imp_policy == 3) {
    da = (uint64_t)(int64_t)wp->calldepth[la] + (1ull << 32);
    db = (uint64_t)(int64_t)wp->calldepth[lb] + (1ull << 32);
  }
  if (da != db) return da > db;  /* the deeper one first */
  return pc_a < pc_b;
}

/* Make a parked path the running one, if any should run before it (or if the
   running one has no lanes left). Returns 0 when the warp has no path at all. */
static int axis_simt_reselect(axis_simt_machine *m, uint32_t w) {
  axis_simt_warp *wp = &m->warp[w];
  for (uint32_t k = 0; k < wp->npaths;)
    if (wp->mask && wp->path_pc[k] == wp->pc && axis_simt_same_tag(wp, wp->mask, wp->path_mask[k])) {
      axis_simt_meet(m, wp, wp->pc, wp->mask, wp->path_mask[k]);
      wp->mask |= wp->path_mask[k];
      wp->path_pc[k] = wp->path_pc[wp->npaths - 1];
      wp->path_mask[k] = wp->path_mask[--wp->npaths];
      ++m->counters.path_merges;
    } else ++k;
  int best = -1;
  for (uint32_t k = 0; k < wp->npaths; ++k) {
    uint64_t bpc = best < 0 ? wp->pc : wp->path_pc[best], bmask = best < 0 ? wp->mask : wp->path_mask[best];
    if (!bmask || axis_simt_path_before(m, w, wp->path_pc[k], wp->path_mask[k], bpc, bmask)) best = (int)k;
  }
  if (best < 0) return wp->mask != 0;
  uint64_t pc = wp->path_pc[best], mask = wp->path_mask[best];
  wp->path_pc[best] = wp->path_pc[wp->npaths - 1];
  wp->path_mask[best] = wp->path_mask[--wp->npaths];
  if (wp->mask) {
    if (axis_simt_at_hint(m, wp->pc) && !axis_simt_at_hint(m, pc)) ++m->counters.hint_waits;
    axis_simt_park(m, wp, wp->pc, wp->mask, 1);
  }
  wp->pc = pc;
  wp->mask = mask;
  wp->stint = 0;
  for (uint32_t l = 0; l < m->lanes; ++l)
    if (mask >> l & 1) wp->aside[l] = 0;
  ++m->counters.path_switches;
  /* Another pc: a fresh fetch, as after a branch -- unless the divergence
     predictor called this split, in which case the front end already knew
     both pcs and which the policy would run. */
  if (m->core->imp_smt) {
    /* Its own front end: it goes on when its lanes may, with no refetch. */
    uint64_t r = axis_simt_path_ready(m, wp, mask);
    wp->ready_at = r > m->now ? r : m->now;
  } else if (!m->foreseen_split && wp->ready_at < m->now + 1 + m->core->branch_penalty)
    wp->ready_at = m->now + 1 + m->core->branch_penalty;
  return 1;
}

/* Execute one instruction for warp w, then charge it. */
static int axis_simt_issue(axis_simt_machine *m, uint32_t w, const axis_simt_decoded *d) {
  axis_simt_warp *wp = &m->warp[w];
  const axis_simt_core *c = m->core;
  uint64_t pc = wp->pc;
  uint64_t mask = wp->mask;
  uint64_t next_pc = pc + 4;
  int have_next = 0;
  uint64_t pred = 0;
  uint64_t lane_pc[AXIS_SIMT_MAX_LANES];
  int diverged = 0;
  uint64_t ran = mask;
  /* Read now: choosing a path decodes other words, and the decode cache may
     hand `d`'s entry to one of them. */
  int depth_step = d->call ? 1 : d->ret ? -1 : 0;
  int relax = d->relax;
  m->acc_n = 0;
  m->acc_write = 0;
  axis_pack_mem mem = { axis_simt_mem_read, axis_simt_mem_write, m };
  /* Vector mode. The warp is one thread: lane 0 holds its scalar registers
     and state, and lane e holds slice e of every vector register. A scalar
     instruction executes once, in lane 0. A vector instruction executes in
     every lane, each reading the thread's scalar sources (lane 0's) and its
     own slice -- or lane 0's slice too, for a broadcast. */
  int vector = wp->vector && c->vec_isa;
  int spread = vector && d->vec;
  uint64_t src0[AXIS_SIMT_MAX_DEPS], st0[64];
  if (vector && !d->vec) {
    if (d->wide)
      return axis_simt_fail(m, "a register wider than a lane's slice, in vector mode: not modelled", w);
    if (d->role != AXIS_SIMT_ROLE_NONE && d->role != AXIS_SIMT_ROLE_TMC && d->role != AXIS_SIMT_ROLE_SYSREAD)
      return axis_simt_fail(m, "warp control other than TMC, in vector mode: not modelled", w);
    mask = 1;
  }
  if (spread) {
    const uint64_t *r0 = axis_simt_lane_regs(m, w, 0);
    for (int32_t i = 0; i < d->nsrc; ++i) src0[i] = d->src[i] < 1000 ? r0[d->src[i]] : 0;
    memcpy(st0, axis_simt_lane_state(m, w, 0), (size_t)m->nstate * sizeof(uint64_t));
  }
  if (spread && d->xlane) {
    int32_t r = 0;
    for (int32_t i = 0; i < d->nsrc && r < 8; ++i)
      if (d->src[i] < 1000 && (d->src_lane >> i & 1)) {
        for (uint32_t l = 0; l < m->lanes; ++l) m->xlane[r][l] = axis_simt_lane_regs(m, w, l)[d->src[i]];
        ++r;
      }
    r = 8;
    for (int32_t s = 0; s < m->nstate && r < AXIS_SIMT_XLANE_REGIONS; ++s)
      if (c->vec_lane_state >> s & 1) {
        for (uint32_t l = 0; l < m->lanes; ++l) m->xlane[r][l] = axis_simt_lane_state(m, w, l)[s];
        ++r;
      }
  }
  for (uint32_t l = 0; l < m->lanes; ++l) {
    if (!(mask >> l & 1)) continue;
    uint64_t *regs = axis_simt_lane_regs(m, w, l);
    uint64_t *st = axis_simt_lane_state(m, w, l);
    uint64_t lane_next = pc + 4;
    uint64_t own[AXIS_SIMT_MAX_DEPS];
    if (spread && l) {
      for (int32_t i = 0; i < d->nsrc; ++i)
        if (d->src[i] < 1000 && (d->bcast || !(d->src_lane >> i & 1))) {
          own[i] = regs[d->src[i]];
          regs[d->src[i]] = src0[i];
        }
      for (int32_t s = 0; s < m->nstate; ++s)
        if (!(c->vec_lane_state >> s & 1)) st[s] = st0[s];
    }
    m->cur_warp = w;
    m->cur_lane = l;
    if (m->st_lane >= 0) st[m->st_lane] = l;
    if (m->st_lanes >= 0) st[m->st_lanes] = m->lanes;
    if (d->role == AXIS_SIMT_ROLE_SYSREAD) {
      uint64_t v = m->hooks.sysreg ? m->hooks.sysreg(m->hooks.ctx, w, l, d->sys_index) : 0;
      if (d->sys_dst_slot >= 0) regs[d->sys_dst_slot] = v;
    } else if (d->role != AXIS_SIMT_ROLE_WSYNC) {
      if (m->st_token >= 0) st[m->st_token] = wp->depth;
      for (int32_t s = 0; s < m->nstate; ++s) m->entries[s].value = st[s];
      axis_pack_exec_result r;
      memset(&r, 0, sizeof r);
      /* A memory instruction may fault in this lane: keep what it would undo. */
      int faultable = m->hooks.fault && d->op && (d->op->loads || d->op->stores);
      uint64_t keep_regs[512];
      uint32_t acc_before = m->acc_n;
      if (faultable && m->slots <= 512) memcpy(keep_regs, regs, (size_t)m->slots * sizeof(uint64_t));
      m->lane_fault = 0;
      m->E->step(d->word, d->isa, regs, m->slots, &mem, pc, m->entries, m->nstate, &r);
      if (m->lane_fault) {
        m->lane_fault = 0;
        if (!c->imp_policy || vector) return axis_simt_fail(m, "a faulting access on a core that is not implicit: not modelled", w);
        if (m->slots <= 512) memcpy(regs, keep_regs, (size_t)m->slots * sizeof(uint64_t));
        m->acc_n = acc_before;  /* nothing of its went to the cache */
        if (m->fault_n < sizeof m->faultq / sizeof m->faultq[0]) {
          uint32_t k = (m->fault_head + m->fault_n++) % (uint32_t)(sizeof m->faultq / sizeof m->faultq[0]);
          m->faultq[k].w = w; m->faultq[k].l = l; m->faultq[k].pc = pc; m->faultq[k].addr = m->fault_addr;
        }
        ++m->counters.faults;
        lane_pc[l] = pc;  /* it stays: state as before (entries not copied back) */
        if (!have_next) { next_pc = pc; have_next = 1; }
        else if (pc != next_pc) diverged = 1;
        continue;
      }
      for (int32_t s = 0; s < m->nstate; ++s) st[s] = m->entries[s].value;
      if (!r.ok || r.trapped) return axis_simt_fail(m, r.trapped && r.trap_cause ? r.trap_cause : "the executor cannot perform this instruction", w);
      lane_next = r.next_pc;
      if (m->st_pred >= 0 && (st[m->st_pred] & 1)) pred |= 1ull << l;
      if (spread && l && d->bcast)
        /* A broadcast lends the lane lane 0's slice of each source; the
           lane's own slice of a register it did not write comes back. */
        for (int32_t i = 0; i < d->nsrc; ++i)
          if (d->src[i] < 1000 && (d->src_lane >> i & 1)) {
            int written = 0;
            for (int32_t k = 0; k < d->ndst; ++k) written |= d->dst[k] == d->src[i];
            if (!written) regs[d->src[i]] = own[i];
          }
    }
    ++m->counters.lane_instrs;
    lane_pc[l] = lane_next;
    if (!have_next) { next_pc = lane_next; have_next = 1; }
    else if (lane_next != next_pc) {
      if (!c->imp_policy || vector)
        return axis_simt_fail(m, "lanes disagree on the next pc: a divergent branch with no SPLIT", w);
      diverged = 1;
    }
  }
  if (spread && d->pflags && c->vec_flag_state >= 0 && m->st_arg >= 0 && m->st_arg2 >= 0) {
    /* A predicate test: first active, none active, last not active. */
    uint64_t any = 0;
    for (uint32_t l = 0; l < m->lanes; ++l) any |= axis_simt_lane_state(m, w, l)[m->st_arg];
    uint64_t first = axis_simt_lane_state(m, w, 0)[m->st_arg] & 1;
    uint64_t last = axis_simt_lane_state(m, w, m->lanes - 1)[m->st_arg2] & 1;
    axis_simt_lane_state(m, w, 0)[c->vec_flag_state] = first << 3 | (uint64_t)(any == 0) << 2 | (last ^ 1) << 1;
  }
  if (spread && d->sum && m->st_arg >= 0) {
    uint64_t total = 0;
    for (uint32_t l = 0; l < m->lanes; ++l) total += axis_simt_lane_state(m, w, l)[m->st_arg];
    for (int32_t i = 0; i < d->ndst; ++i)
      if (d->dst_lane >> i & 1)
        for (uint32_t l = 0; l < m->lanes; ++l) axis_simt_lane_regs(m, w, l)[d->dst[i]] = l ? 0 : total;
  }
  if (vector && !d->vec)
    /* A scalar write to a vector register clears the rest of it. */
    for (int32_t i = 0; i < d->ndst; ++i)
      if (d->dst_lane >> i & 1)
        for (uint32_t l = 1; l < m->lanes; ++l) axis_simt_lane_regs(m, w, l)[d->dst[i]] = 0;
  ++m->counters.warp_instrs;
  int last = axis_simt_last_lane(mask);
  uint64_t *last_st = last >= 0 ? axis_simt_lane_state(m, w, (uint32_t)last) : NULL;
  uint64_t arg = last_st && m->st_arg >= 0 ? last_st[m->st_arg] : 0;
  uint64_t arg2 = last_st && m->st_arg2 >= 0 ? last_st[m->st_arg2] : 0;

  /* ---- timing ---- */
  const axis_simt_unit *u = d->unit >= 0 ? &c->units[d->unit] : NULL;
  uint32_t unit_lanes = u && u->lanes ? u->lanes : m->lanes;
  uint32_t occupancy = (m->lanes + unit_lanes - 1) / unit_lanes;
  uint32_t latency = d->latency ? d->latency : (u && u->latency) ? u->latency : (d->op ? d->op->latency : 1);
  if (latency == 0) latency = 1;
  uint32_t unit_latency = latency;
  latency += c->pipeline;
  /* Coalesce: lane addresses in one line are one request, in first-touch order. */
  uint64_t lines[AXIS_SIMT_MAX_LINES];
  uint32_t n = 0;
  for (uint32_t i = 0; i < m->acc_n; ++i) {
    uint64_t line = m->acc_addr[i] / c->line;
    uint32_t k = 0;
    while (k < n && lines[k] != line) ++k;
    if (k == n) lines[n++] = line;
  }
  if (m->acc_n) {
    m->counters.mem_requests += 1;
    m->counters.mem_lines += n;
  }
  int control = d->role != AXIS_SIMT_ROLE_NONE && d->role != AXIS_SIMT_ROLE_SYSREAD;
  if (d->op && d->op->writes_pc) control = 1;
  if (c->ooo_rob) {
    /* Out of order: into the window. It has executed; it starts, and is
       charged, when its producers are done and a unit is free
       (axis_simt_window_tick). */
    axis_simt_uop *q = &wp->rob[wp->rob_next % c->ooo_rob];
    memset(q, 0, sizeof *q);
    q->unit = d->unit;
    q->occupancy = occupancy;
    q->latency = latency;
    q->unit_latency = unit_latency;
    q->key = pc ^ ((uint64_t)w << 48);
    q->write = m->acc_write;
    q->nlines = n < AXIS_SIMT_UOP_LINES ? n : AXIS_SIMT_UOP_LINES;
    memcpy(q->lines, lines, q->nlines * sizeof(uint64_t));
    q->lanes = mask;
    int smt = c->imp_smt && wp->lreg_writer && !vector;
    for (int32_t i = 0; i < d->nsrc; ++i) {
      int32_t sl = d->src[i];
      if (smt) {
        /* Renamed per lane: wait for the writer of this register in each
           lane it runs for, not for another path's write to other lanes. */
        for (uint32_t l = 0; l < m->lanes; ++l) {
          if (!(mask >> l & 1)) continue;
          uint64_t writer = sl >= 1000 ? wp->lstate_writer[(size_t)l * 64 + (size_t)(sl - 1000)]
                                       : wp->lreg_writer[(size_t)l * (size_t)m->slots + (size_t)sl];
          if (!writer || writer - 1 < wp->rob_head) continue;
          int known = 0;
          for (int32_t k = 0; k < q->ndep; ++k) known |= q->dep[k] == writer - 1;
          if (!known && q->ndep < AXIS_SIMT_UOP_DEPS) q->dep[q->ndep++] = writer - 1;
        }
        continue;
      }
      uint64_t writer = sl >= 1000 ? wp->state_writer[sl - 1000] : wp->reg_writer[sl];
      if (writer && writer - 1 >= wp->rob_head) q->dep[q->ndep++] = writer - 1;
    }
    /* A write under a partial mask merges into the old value: the lanes it
       does not cover keep it. So it waits for the previous writer too. */
    int partial = wp->npaths > 0 || wp->depth > 0;
    for (int32_t i = 0; i < d->ndst; ++i) {
      int32_t sl = d->dst[i];
      uint64_t *writer = sl >= 1000 ? &wp->state_writer[sl - 1000] : &wp->reg_writer[sl];
      if (smt) {
        /* Per lane, a masked write is a whole write of each lane it covers. */
        if (partial) ++m->counters.partial_writes;
        for (uint32_t l = 0; l < m->lanes; ++l)
          if (mask >> l & 1) {
            if (sl >= 1000) wp->lstate_writer[(size_t)l * 64 + (size_t)(sl - 1000)] = wp->rob_next + 1;
            else wp->lreg_writer[(size_t)l * (size_t)m->slots + (size_t)sl] = wp->rob_next + 1;
          }
        *writer = wp->rob_next + 1;
        q->dst[q->ndst++] = sl;
        continue;
      }
      if (partial && *writer && *writer - 1 >= wp->rob_head) {
        if (c->ooo_merge) q->dep[q->ndep++] = *writer - 1;
        ++m->counters.partial_writes;
      }
      *writer = wp->rob_next + 1;
      q->dst[q->ndst++] = sl;
    }
    if (c->ooo_memorder && m->acc_n) {
      /* A load waits for the youngest older store to any 8 bytes it reads:
         it takes the value from that store when the store is done. */
      for (uint32_t i = 0; i < m->acc_n; ++i) {
        uint64_t g = m->acc_addr[i] >> 3;
        uint32_t h = (uint32_t)((g * 0x9e3779b97f4a7c15ull) >> 52) % AXIS_SIMT_STORE_TABLE;
        if (m->acc_write) { wp->store_at[h] = g; wp->store_seq[h] = wp->rob_next + 1; continue; }
        uint64_t writer = wp->store_seq[h];
        if (!writer || wp->store_at[h] != g || writer - 1 < wp->rob_head) continue;
        int known = 0;
        for (int32_t k = 0; k < q->ndep; ++k) known |= q->dep[k] == writer - 1;
        if (!known && q->ndep < AXIS_SIMT_UOP_DEPS) { q->dep[q->ndep++] = writer - 1; ++m->counters.store_waits; }
      }
    }
    /* The front end runs on, and waits only for what it cannot predict:
       every branch with no predictor, a branch the predictor got wrong, and
       always a divergence or a warp-control instruction. */
    int unpredicted = !c->ooo_predict;
    int foreseen = 0;  /* a divergence the divergence predictor called */
    if (control && d->role == AXIS_SIMT_ROLE_NONE && c->ooo_divergence) {
      /* Will this branch split the warp? Two-bit counters by pc. Right
         about a split, the front end goes on: both pcs are known. Wrong
         either way, it waits as it would with none. */
      uint8_t *ctr = &m->divpred[(pc >> 2) & (c->ooo_entries - 1)];
      int said = *ctr >= 2;
      foreseen = diverged && said;
      m->foreseen_split = foreseen;
      if (said != diverged) { unpredicted = 1; ++m->counters.divergence_mispredicts; }
      if (diverged) { if (*ctr < 3) ++*ctr; } else if (*ctr > 0) --*ctr;
    }
    if (diverged) ++m->counters.divergences;
    if (control && d->role == AXIS_SIMT_ROLE_NONE && !diverged) {
      ++m->counters.branches;
      if (c->ooo_predict == 2) {
        /* Two-bit counters by pc. An unconditional branch is "taken" every
           time and costs two misses to learn. */
        uint8_t *ctr = &m->bimodal[(pc >> 2) & (c->ooo_entries - 1)];
        int taken = next_pc != pc + 4;
        unpredicted |= (*ctr >= 2) != taken;
        if (taken) { if (*ctr < 3) ++*ctr; } else if (*ctr > 0) --*ctr;
      }
      m->counters.mispredicts += (uint64_t)unpredicted;
    }
    q->front = control && (unpredicted || (diverged && !foreseen) ||
                           (d->role != AXIS_SIMT_ROLE_NONE && d->role != AXIS_SIMT_ROLE_SYSREAD));
    wp->ready_at = q->front ? UINT64_MAX : m->now;
    if (smt)
      for (uint32_t l = 0; l < m->lanes; ++l)
        if (mask >> l & 1) wp->front_ready[l] = wp->ready_at;
    ++wp->rob_next;
  } else {
    uint64_t done = axis_simt_charge(m, d->unit, occupancy, latency, unit_latency, lines, n, pc ^ ((uint64_t)w << 48), m->acc_write);
    for (int32_t i = 0; i < d->ndst; ++i) {
      int32_t s = d->dst[i];
      if (s >= 1000) wp->state_ready[s - 1000] = done; else wp->reg_ready[s] = done;
    }
    if (done > wp->inflight_until) wp->inflight_until = done;
    /* A warp issues one instruction a cycle; after control flow it waits for
       the outcome, as a SIMT front end without prediction does. */
    uint64_t gap = occupancy > c->issue_interval ? occupancy : c->issue_interval;
    wp->ready_at = control ? done + c->branch_penalty : m->now + gap;
  }
  wp->pc = next_pc;

  /* ---- the warp ---- */
  switch (d->role) {
  case AXIS_SIMT_ROLE_TMC:
    if (wp->npaths) {
      /* With paths parked, a TMC speaks for the running path's threads only:
         it can stop them, not wake a lane that is parked somewhere else. */
      wp->mask = arg & mask;
    } else {
      wp->mask = arg & m->full_mask;
      /* A lane it wakes continues from here, at the waker's call depth. */
      if (last >= 0)
        for (uint32_t l = 0; l < m->lanes; ++l)
          if ((wp->mask & ~mask) >> l & 1) wp->calldepth[l] = wp->calldepth[last];
    }
    if (!wp->mask && !(wp->npaths && axis_simt_reselect(m, w))) axis_simt_finish_warp(m, w);
    break;
  case AXIS_SIMT_ROLE_WSPAWN:
    for (uint32_t k = 1; k < arg && k < m->warps; ++k)
      if (!m->warp[k].active) axis_simt_start_warp(m, k, arg2, 1);
      else m->warp[k].spawn_pc = arg2;  /* still retiring from the last spawn (WSYNC): when it has */
    break;
  case AXIS_SIMT_ROLE_SPLIT: {
    uint64_t then_m = mask & pred, else_m = mask & ~pred;
    ++m->counters.splits;
    if (then_m && else_m) {
      if (wp->depth >= c->stack || wp->depth >= AXIS_SIMT_MAX_STACK)
        return axis_simt_fail(m, "reconvergence stack overflow", w);
      axis_simt_ipdom *e = &wp->stack[wp->depth++];
      e->orig_mask = mask;
      e->else_pc = next_pc;
      e->fallthrough = 0;
      /* The smaller group runs first, as Vortex does. */
      wp->mask = axis_simt_popcount(then_m) <= axis_simt_popcount(else_m) ? then_m : else_m;
      ++m->counters.divergent_splits;
    }
    break;
  }
  case AXIS_SIMT_ROLE_JOIN:
    ++m->counters.joins;
    if (arg < wp->depth) {
      axis_simt_ipdom *e = &wp->stack[wp->depth - 1];
      if (!e->fallthrough) {
        wp->mask = ~mask & e->orig_mask;
        wp->pc = e->else_pc;
        e->fallthrough = 1;
      } else {
        wp->mask = e->orig_mask;
        --wp->depth;
      }
    }
    break;
  case AXIS_SIMT_ROLE_PRED: {
    ++m->counters.preds;
    uint64_t keep = mask & pred;
    wp->mask = keep ? keep : (arg & m->full_mask);
    if (!wp->mask && !(wp->npaths && axis_simt_reselect(m, w))) axis_simt_finish_warp(m, w);
    break;
  }
  case AXIS_SIMT_ROLE_BAR: {
    if (c->imp_policy && wp->npaths && !vector) {
      /* A warp arrives at a barrier when all of it does: a path that gets
         here while others of its warp are parked waits, set aside, and runs
         the barrier again once they have gone (stopped, or here too). Which
         path runs first is the policy's -- or, with paths issuing as SMT
         threads, whichever is ready -- so the barrier cannot assume it. */
      wp->pc = pc;
      for (uint32_t l = 0; l < m->lanes; ++l)
        if (wp->mask >> l & 1) wp->aside[l] = m->now + 1;
      ++m->counters.bar_waits;
      break;
    }
    uint32_t id = (uint32_t)(arg % AXIS_SIMT_MAX_BARRIERS);
    ++m->counters.barriers;
    wp->waiting_bar = (int32_t)id + 1;
    if (++m->bar_count[id] >= arg2) {
      m->bar_count[id] = 0;
      for (uint32_t k = 0; k < m->warps; ++k)
        if (m->warp[k].waiting_bar == (int32_t)id + 1) {
          m->warp[k].waiting_bar = 0;
          if (m->warp[k].ready_at < m->now + 1) m->warp[k].ready_at = m->now + 1;
        }
    }
    break;
  }
  case AXIS_SIMT_ROLE_WSYNC:
    wp->draining = 1;
    break;
  default:
    break;
  }
  if (c->imp_policy && !vector) {
    if (depth_step)
      for (uint32_t l = 0; l < m->lanes; ++l)
        if (ran >> l & 1) wp->calldepth[l] += depth_step;
    if (diverged) {
      /* The lanes go where each of them goes: one path a distinct pc. The
         first lane's stays the running one until the policy says otherwise. */
      ++m->counters.implicit_splits;
      uint64_t stay = 0;
      for (uint32_t l = 0; l < m->lanes; ++l) {
        if (!(ran >> l & 1)) continue;
        if (lane_pc[l] == next_pc) stay |= 1ull << l;
        else axis_simt_park(m, wp, lane_pc[l], 1ull << l, 0);  /* lanes leaving together are one path */
      }
      wp->mask = stay;
    }
    if (d->sevl) wp->event |= ran;
    if (d->sev) {
      /* Every lane of every warp: a sleeper wakes, the rest keep the event. */
      for (uint32_t k = 0; k < m->warps; ++k) {
        axis_simt_warp *wk = &m->warp[k];
        wk->event |= m->full_mask & ~wk->asleep;
        wk->asleep = 0;
        if (wk->dormant) {
          wk->dormant = 0;
          if (wk->ready_at < m->now + 1) wk->ready_at = m->now + 1;
          if (k != w && wk->npaths) axis_simt_reselect(m, k);
        }
      }
    }
    if (d->wfe && wp->active) {
      /* A lane with its event set clears it and goes on; one without sleeps
         where it is (the next pc), its path set apart from the awake. */
      uint64_t sleepers = ran & wp->mask & ~wp->event;
      wp->event &= ~ran;
      if (sleepers) {
        m->counters.sleeps += axis_simt_popcount(sleepers);
        wp->asleep |= sleepers;
        if (sleepers != wp->mask) {
          wp->mask &= ~sleepers;
          axis_simt_park(m, wp, wp->pc, sleepers, 0);
        }
      }
    }
    if (wp->active && wp->npaths && relax) {
      /* A spin-loop hint: this path is waiting for something, so it goes
         behind every path that is not -- including one the policy prefers. */
      for (uint32_t l = 0; l < m->lanes; ++l)
        if (wp->mask >> l & 1) wp->aside[l] = m->now + 1;
      wp->stint = 0;
      ++m->counters.relax_switches;
    } else if (wp->active && wp->npaths && c->imp_progress && ++wp->stint >= c->imp_progress) {
      /* Forward progress: set the running path aside. A path spinning on a
         flag that a parked path would set otherwise holds the warp for as
         long as the policy prefers it -- for ever, if it does at every pc of
         the loop. */
      for (uint32_t l = 0; l < m->lanes; ++l)
        if (wp->mask >> l & 1) wp->aside[l] = m->now + 1;
      wp->stint = 0;
      ++m->counters.progress_switches;
    }
    if (wp->active && wp->npaths) axis_simt_reselect(m, w);
    else wp->stint = 0;
    /* Every path asleep (an awake one would have been chosen): the warp waits. */
    wp->dormant = wp->active && (wp->mask & wp->asleep) != 0;
    m->foreseen_split = 0;
  }
  return 0;
}

/* ---- threads an OS places ------------------------------------------------- */

uint64_t axis_simt_now(const axis_simt_machine *m) { return m->now; }

int axis_simt_share_memsys(axis_simt_machine *m, void *handle) {
  axis_ms *ms = (axis_ms *)handle;
  if (!m || !ms || ms->layout != AXIS_MS_LAYOUT) return 0;
  int32_t port = axis_ms_port(ms, m->core->name);
  if (port < 0) return 0;
  if (m->ms) axis_ms_free(m->ms);
  m->ms = ms;
  ms->refs++;
  m->ms_port = port;
  m->ms_system = -1;  /* not one of this library's tables: never rebuilt */
  return 1;
}

int axis_simt_take_fault(axis_simt_machine *m, uint32_t *w, uint32_t *l, uint64_t *pc, uint64_t *addr) {
  if (!m->fault_n) return 0;
  uint32_t k = m->fault_head;
  *w = m->faultq[k].w; *l = m->faultq[k].l; *pc = m->faultq[k].pc; *addr = m->faultq[k].addr;
  m->fault_head = (k + 1) % (uint32_t)(sizeof m->faultq / sizeof m->faultq[0]);
  --m->fault_n;
  return 1;
}

int axis_simt_lane_live(const axis_simt_machine *m, uint32_t w, uint32_t l) {
  if (w >= m->warps || l >= m->lanes || !m->warp[w].active) return 0;
  const axis_simt_warp *wp = &m->warp[w];
  if (wp->mask >> l & 1) return 1;
  for (uint32_t k = 0; k < wp->npaths; ++k)
    if (wp->path_mask[k] >> l & 1) return 1;
  return 0;
}

uint64_t axis_simt_lane_pc(const axis_simt_machine *m, uint32_t w, uint32_t l) {
  if (!axis_simt_lane_live(m, w, l)) return ~0ull;
  const axis_simt_warp *wp = &m->warp[w];
  if (wp->mask >> l & 1) return wp->pc;
  for (uint32_t k = 0; k < wp->npaths; ++k)
    if (wp->path_mask[k] >> l & 1) return wp->path_pc[k];
  return ~0ull;
}

/* A lane leaves at an instruction boundary. What it issued has executed (the
   engine executes at issue); what is still in a unit or the window finishes
   without it, as a pipeline drains on an exception. */
uint64_t axis_simt_lane_out(axis_simt_machine *m, uint32_t w, uint32_t l, int32_t *depth) {
  if (!axis_simt_lane_live(m, w, l)) return ~0ull;
  axis_simt_warp *wp = &m->warp[w];
  uint64_t bit = 1ull << l, pc = ~0ull;
  if (depth) *depth = wp->calldepth[l];
  if (wp->depth) { axis_simt_fail(m, "a lane leaving a warp inside a SPLIT: not modelled", w); return ~0ull; }
  if (wp->mask & bit) {
    pc = wp->pc;
    wp->mask &= ~bit;
    if (!wp->mask) {
      if (wp->npaths) axis_simt_reselect(m, w);
      else axis_simt_finish_warp(m, w);
    }
  } else {
    for (uint32_t k = 0; k < wp->npaths; ++k)
      if (wp->path_mask[k] & bit) {
        pc = wp->path_pc[k];
        if (!(wp->path_mask[k] &= ~bit)) {
          wp->path_pc[k] = wp->path_pc[wp->npaths - 1];
          wp->path_mask[k] = wp->path_mask[--wp->npaths];
        }
        break;
      }
  }
  wp->aside[l] = 0;
  wp->asleep &= ~bit;
  wp->event &= ~bit;
  wp->dormant = wp->active && (wp->mask & wp->asleep) != 0;
  return pc;
}

int axis_simt_lane_in(axis_simt_machine *m, uint32_t w, uint32_t l, uint64_t pc, uint32_t tag, int32_t depth) {
  if (w >= m->warps || l >= m->lanes || axis_simt_lane_live(m, w, l)) return 0;
  if (!m->core->imp_policy) { axis_simt_fail(m, "placing one lane at a time needs an implicit core", w); return 0; }
  axis_simt_warp *wp = &m->warp[w];
  if (!wp->active) {
    axis_simt_start_warp(m, w, pc, 1ull << l);
  } else {
    wp->tag[l] = tag;  /* before parking: parking merges by tag */
    axis_simt_park(m, wp, pc, 1ull << l, 0);
    wp->aside[l] = 0;
  }
  wp->tag[l] = tag;
  wp->calldepth[l] = depth;
  wp->front_ready[l] = 0;
  if (wp->dormant) {
    /* An awake thread arrives in a warp that slept: it runs. */
    axis_simt_reselect(m, w);
    wp->dormant = (wp->mask & wp->asleep) != 0;
    if (wp->ready_at < m->now + 1) wp->ready_at = m->now + 1;
  }
  return 1;
}

/* Advance the machine one cycle. Returns 1 while work remains, 0 when every
   warp has retired and everything issued has completed, -1 on an error. */
int axis_simt_cycle(axis_simt_machine *m) {
  const axis_simt_core *c = m->core;
  int any = 0;
  if (c->ooo_rob) {
    axis_simt_window_tick(m);
    if (m->error[0]) return -1;  /* an instruction the window started failed (a refused access) */
    for (uint32_t w = 0; w < m->warps; ++w) any |= m->warp[w].rob_head != m->warp[w].rob_next;
    if (any) {
      int active = 0;
      for (uint32_t w = 0; w < m->warps; ++w) active |= m->warp[w].active;
      if (!active) { ++m->now; ++m->counters.cycles; return 1; }  /* only the windows are left */
    }
  }
  for (uint32_t w = 0; w < m->warps; ++w) any |= m->warp[w].active;
  if (!any) return m->now >= m->done_at ? 0 : (++m->now, ++m->counters.cycles, 1);
  if (c->imp_smt)
    /* Paths as SMT threads: a warp whose running path waits on its branch
       goes on with a parked path that can, this cycle, without a refetch. */
    for (uint32_t w = 0; w < m->warps; ++w) {
      axis_simt_warp *wp = &m->warp[w];
      if (!wp->active || wp->dormant || !wp->npaths || wp->ready_at <= m->now) continue;
      if (axis_simt_fronts_full(m, wp)) continue;
      uint64_t pc0 = wp->pc, mask0 = wp->mask;
      axis_simt_reselect(m, w);
      if (wp->pc != pc0 || wp->mask != mask0) ++m->counters.smt_switches;
    }
  uint32_t issued = 0;
  uint32_t width = c->issue_width ? c->issue_width : 1;
  int taken[AXIS_SIMT_MAX_WARPS] = {0};
  uint64_t first_mask[AXIS_SIMT_MAX_WARPS] = {0};
  int several[AXIS_SIMT_MAX_WARPS] = {0};
  while (issued < width) {
    int pick = -1;
    /* gto: the warp that issued last, while it can; then the oldest ready one.
       rr: the next ready warp after the last one to issue. */
    for (uint32_t step = 0; step < m->warps; ++step) {
      uint32_t w;
      if (c->greedy) {
        if (step == 0) w = m->last_warp;
        else {
          /* oldest by start cycle, ties by index */
          int best = -1;
          for (uint32_t k = 0; k < m->warps; ++k) {
            axis_simt_warp *wk = &m->warp[k];
            if (taken[k] || !wk->active || wk->dormant || wk->waiting_bar || wk->ready_at > m->now) continue;
            if (wk->draining && (wk->inflight_until > m->now || wk->rob_head != wk->rob_next)) continue;
            const axis_simt_decoded *dk;
            int ok = 1;
            uint32_t word = m->hooks.fetch(m->hooks.ctx, wk->pc, &ok);
            if (!ok) continue;
            dk = axis_simt_decode(m, word);
            if (dk->index < 0 && dk->role == AXIS_SIMT_ROLE_NONE) continue;
            if (!axis_simt_ready(m, wk, dk)) continue;
            if (best < 0 || wk->started < m->warp[best].started) best = (int)k;
          }
          pick = best;
          break;
        }
      } else {
        w = (m->last_warp + 1 + step) % m->warps;
      }
      axis_simt_warp *wp = &m->warp[w];
      if (taken[w] || !wp->active || wp->dormant || wp->waiting_bar || wp->ready_at > m->now) continue;
      if (wp->draining && (wp->inflight_until > m->now || wp->rob_head != wp->rob_next)) continue;
      int ok = 1;
      uint32_t word = m->hooks.fetch(m->hooks.ctx, wp->pc, &ok);
      if (!ok) return axis_simt_fail(m, "fetch refused", w);
      const axis_simt_decoded *d = axis_simt_decode(m, word);
      if (!axis_simt_ready(m, wp, d)) continue;
      pick = (int)w;
      break;
    }
    if (pick < 0) break;
    axis_simt_warp *wp = &m->warp[pick];
    wp->draining = 0;
    int ok = 1;
    uint32_t word = m->hooks.fetch(m->hooks.ctx, wp->pc, &ok);
    const axis_simt_decoded *d = axis_simt_decode(m, word);
    if (d->index < 0) return axis_simt_fail(m, "undecodable instruction", (uint32_t)pick);
    taken[pick] = !c->ooo_rob;  /* out of order, a warp may dispatch several in a cycle */
    m->last_warp = (uint32_t)pick;
    {
      /* AXIS_SIMT_TRACE=n: the first n issues -- cycle, warp, mask, pc, mnemonic */
      static long trace_left = -1;
      if (trace_left < 0) { const char *e = getenv("AXIS_SIMT_TRACE"); trace_left = e ? atol(e) : 0; }
      if (trace_left > 0) {
        --trace_left;
        fprintf(stderr, "SIMT %llu w%d m%llx pc=%llx %s\n", (unsigned long long)m->now, pick,
                (unsigned long long)wp->mask, (unsigned long long)wp->pc, m->L->mnemonic(d->index));
      }
    }
    if (!first_mask[pick]) first_mask[pick] = wp->mask;
    else if (first_mask[pick] != wp->mask) several[pick] = 1;
    if (axis_simt_issue(m, (uint32_t)pick, d) < 0) return -1;
    ++issued;
  }
  if (m->error[0]) return -1;
  if (!issued) ++m->counters.idle_cycles;
  for (uint32_t w = 0; w < m->warps; ++w) m->counters.smt_cycles += (uint64_t)several[w];
  for (uint32_t w = 0; w < m->warps; ++w) m->counters.dormant_cycles += (uint64_t)(m->warp[w].active && m->warp[w].dormant);
  ++m->now;
  ++m->counters.cycles;
  return 1;
}

/* Run until every warp has retired and everything it issued has completed,
   or `limit` cycles (0: no limit). 0 done, 1 limit reached, -1 error. */
int axis_simt_run(axis_simt_machine *m, uint64_t limit) {
  uint64_t start = m->now;
  for (;;) {
    int r = axis_simt_cycle(m);
    if (r <= 0) return r;
    if (limit && m->now - start >= limit) return 1;
  }
}
