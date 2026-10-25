/*
 * cachesim: measured ladder-cache usage of one MTL-aware resolver.
 *
 * A signer holds one MTL tree. A resolver (public-key-only context) replays a
 * stream of queries and keeps the most recent verified signed ladder in its
 * cache. Every verification is a real call into the reference library; the
 * counters, byte totals and timings written here are measurements of this
 * replay, not model outputs.
 *
 * Retrieval follows draft-fregly-dnsop-slh-dsa-mtl-dnssec-06, section 6.2: the
 * resolver first asks without the mtl-mode-full option and receives a condensed
 * signature. If its cached ladder covers the record and has not expired, it
 * verifies against the cache (a hit). Otherwise it asks again with the option
 * and receives the full signature (a miss), verifies it, and caches the ladder.
 * A miss therefore delivers a condensed signature and a full signature.
 *
 * Optional zone growth appends records to the same tree and re-signs the
 * ladder. Signatures served after growth are computed against the new ladder;
 * the MTL draft (draft-harvey-cfrg-mtl-mode-09, section 6.8) says they remain
 * verifiable against an older ladder that covers the record. Every such check
 * is attempted, and any failure is counted as compat_fail.
 *
 * Query popularity is Zipf(s) over published records, ranked by a seeded
 * permutation. Ladder TTL is counted in queries.
 */
#include "common.h"
#include <math.h>

typedef struct {
    char        algorithm[256];
    const char *records_path;
    const char *output;
    size_t      initial;      /* records signed before the first query */
    uint64_t    queries;
    double      zipf_s;
    uint64_t    ttl;          /* queries; 0 = no expiry */
    uint64_t    growth_every; /* queries between growth events; 0 = none */
    size_t      growth_size;  /* records appended per growth event */
    uint64_t    seed;
} config_t;

static void usage(void)
{
    fprintf(stderr,
        "usage: cachesim --records FILE --initial N --queries Q --output FILE.csv\n"
        "                [--zipf S] [--ttl T] [--growth-every G --growth-size A]\n"
        "                [--seed S] [--algorithm ALG]\n");
    exit(2);
}

static void parse_args(int argc, char **argv, config_t *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->algorithm, sizeof(c->algorithm), "%s", LL_DEFAULT_ALG);
    c->zipf_s = 1.0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (!v) usage();
        if      (!strcmp(a, "--algorithm"))    snprintf(c->algorithm, sizeof(c->algorithm), "%s", v);
        else if (!strcmp(a, "--records"))      c->records_path = v;
        else if (!strcmp(a, "--output"))       c->output = v;
        else if (!strcmp(a, "--initial"))      c->initial = strtoul(v, NULL, 10);
        else if (!strcmp(a, "--queries"))      c->queries = strtoull(v, NULL, 10);
        else if (!strcmp(a, "--zipf"))         c->zipf_s = strtod(v, NULL);
        else if (!strcmp(a, "--ttl"))          c->ttl = strtoull(v, NULL, 10);
        else if (!strcmp(a, "--growth-every")) c->growth_every = strtoull(v, NULL, 10);
        else if (!strcmp(a, "--growth-size"))  c->growth_size = strtoul(v, NULL, 10);
        else if (!strcmp(a, "--seed"))         c->seed = strtoull(v, NULL, 10);
        else usage();
        i++;
    }
    if (!c->records_path || !c->output || c->initial < 1 || c->queries < 1 || c->zipf_s < 0)
        usage();
    if ((c->growth_every == 0) != (c->growth_size == 0))
        die("--growth-every and --growth-size must be given together");
}

/* splitmix64: small, seedable, good enough for workload generation. */
static uint64_t rng_state;
static uint64_t rng_next(void)
{
    uint64_t z = (rng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static double rng_unit(void) { return (double)(rng_next() >> 11) * (1.0 / 9007199254740992.0); }

/* Cumulative Zipf weights over the first `published` records. */
static void build_cdf(double *cdf, const size_t *rank, size_t published, double s)
{
    double acc = 0;
    for (size_t i = 0; i < published; i++) {
        acc += 1.0 / pow((double)rank[i] + 1.0, s);
        cdf[i] = acc;
    }
    for (size_t i = 0; i < published; i++) cdf[i] /= acc;
}

static size_t draw(const double *cdf, size_t published)
{
    double u = rng_unit();
    size_t lo = 0, hi = published - 1;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (cdf[mid] < u) lo = mid + 1; else hi = mid;
    }
    return lo;
}

static void sign_ladder(MTLLIB_CTX *ctx, MTLLIB_BUFFER **ladder, uint64_t *ns)
{
    if (*ladder) mtllib_buffer_free(*ladder);
    *ladder = buf_new(mtllib_sign_get_signed_ladder_length(ctx));
    uint64_t t0 = now_ns();
    if (mtllib_sign_get_signed_ladder(ctx, *ladder) != MTLLIB_OK) die("mtllib_sign_get_signed_ladder failed");
    *ns += now_ns() - t0;
}

int main(int argc, char **argv)
{
    config_t c;
    parse_args(argc, argv, &c);
    const uint64_t started = now_ns();

    const uint64_t events = c.growth_every ? (c.queries - 1) / c.growth_every : 0;
    const size_t pool = c.initial + (size_t)events * c.growth_size;
    records_t recs;
    records_load(c.records_path, pool, &recs);

    rng_state = c.seed ? c.seed : 1;
    size_t *rank = xcalloc(pool, sizeof(size_t));   /* rank[record] */
    size_t *perm = xcalloc(pool, sizeof(size_t));
    for (size_t i = 0; i < pool; i++) perm[i] = i;
    for (size_t i = pool - 1; i > 0; i--) {          /* Fisher-Yates */
        size_t j = (size_t)(rng_next() % (i + 1));
        size_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
    }
    for (size_t i = 0; i < pool; i++) rank[perm[i]] = i;
    double *cdf = xcalloc(pool, sizeof(double));

    /* Signer: initial batch and first ladder. */
    MTLLIB_CTX *ctx = NULL;
    if (mtllib_key_new(c.algorithm, &ctx) != MTLLIB_OK || !ctx) die("mtllib_key_new failed");
    MTLLIB_BUFFER **msg = xcalloc(pool, sizeof(*msg));
    MTL_HANDLE **h = xcalloc(pool, sizeof(*h));
    size_t published = 0;
    uint64_t signer_append_ns = 0, signer_ladder_ns = 0, ladder_signs = 0;
    for (; published < c.initial; published++) {
        msg[published] = buf_copy(recs.data[published], recs.len[published]);
        uint64_t t0 = now_ns();
        if (mtllib_sign_append(ctx, msg[published], &h[published]) != MTLLIB_OK) die("append failed");
        signer_append_ns += now_ns() - t0;
    }
    MTLLIB_BUFFER *ladder = NULL;
    sign_ladder(ctx, &ladder, &signer_ladder_ns);
    ladder_signs++;
    uint64_t version = 1;
    size_t ladder_covers = published;
    build_cdf(cdf, rank, published, c.zipf_s);

    /* Resolver. */
    MTLLIB_CTX *v = NULL;
    MTLLIB_BUFFER *cache = NULL;
    uint64_t cache_version = 0, cache_since = 0;
    size_t cache_covers = 0;

    uint64_t hits = 0, miss_cold = 0, miss_expired = 0, miss_uncovered = 0, compat_fail = 0;
    uint64_t hits_on_old_ladder = 0;
    uint64_t bytes_condensed = 0, bytes_full = 0, verify_hit_ns = 0, verify_miss_ns = 0;
    uint64_t peak_cache = 0, ladder_fetches = 0;

    mkdirs_for(c.output);
    FILE *csv = fopen(c.output, "w");
    if (!csv) die("cannot write %s", c.output);
    fprintf(csv,
        "# LadderLens cachesim. One row per query. bytes_delivered = signature bytes sent to the resolver.\n"
        "query,record_index,published,ladder_version,cached_version,event,reason,"
        "condensed_bytes,full_bytes,bytes_delivered,verify_ns,cache_bytes\n");

    for (uint64_t q = 0; q < c.queries; q++) {
        if (c.growth_every && q > 0 && q % c.growth_every == 0) {
            for (size_t a = 0; a < c.growth_size; a++, published++) {
                msg[published] = buf_copy(recs.data[published], recs.len[published]);
                uint64_t t0 = now_ns();
                if (mtllib_sign_append(ctx, msg[published], &h[published]) != MTLLIB_OK) die("append failed");
                signer_append_ns += now_ns() - t0;
            }
            sign_ladder(ctx, &ladder, &signer_ladder_ns);
            ladder_signs++;
            version++;
            ladder_covers = published;
            build_cdf(cdf, rank, published, c.zipf_s);
        }

        const size_t r = draw(cdf, published);
        MTLLIB_BUFFER *cond = buf_new(mtllib_sign_get_condensed_sig_length(ctx, h[r]));
        if (mtllib_sign_get_condensed_sig(ctx, h[r], cond) != MTLLIB_OK) die("condensed signature failed");
        const size_t clen = mtllib_buffer_in_use(cond);
        if (!v) v = verifier_from(ctx, c.algorithm, cond);

        const uint64_t cached_before = cache ? cache_version : 0;
        const char *event, *reason = "";
        uint64_t delivered = clen, full_len = 0, vns = 0;
        bytes_condensed += clen;

        int hit = 0;
        if (!cache) {
            reason = "cold_start";
        } else if (c.ttl && q - cache_since >= c.ttl) {
            reason = "expired";
        } else if (r >= cache_covers) {
            reason = "not_covered";
        } else {
            size_t out = 0;
            uint64_t t0 = now_ns();
            MTLLIB_STATUS st = mtllib_verify(v, msg[r], cond, cache, &out);
            vns = now_ns() - t0;
            if (st == MTLLIB_OK) {
                hit = 1;
                if (cache_version < version) hits_on_old_ladder++;
            } else {
                compat_fail++;
                reason = "compat_fail";
            }
        }

        if (hit) {
            hits++;
            verify_hit_ns += vns;
            event = "hit";
        } else {
            if      (!strcmp(reason, "cold_start")) miss_cold++;
            else if (!strcmp(reason, "expired"))    miss_expired++;
            else if (!strcmp(reason, "not_covered")) miss_uncovered++;
            MTLLIB_BUFFER *full = buf_concat(cond, ladder);
            full_len = mtllib_buffer_in_use(full);
            size_t out = 0;
            uint64_t t0 = now_ns();
            MTLLIB_STATUS st = mtllib_verify(v, msg[r], full, NULL, &out);
            vns = now_ns() - t0;
            if (!verify_ok(st)) die("full signature rejected at query %" PRIu64 " (status %d)", q, (int)st);
            verify_miss_ns += vns;
            bytes_full += full_len;
            delivered += full_len;
            ladder_fetches++;
            if (cache) mtllib_buffer_free(cache);
            cache = buf_copy(mtllib_buffer_data_ptr(ladder), mtllib_buffer_in_use(ladder));
            cache_version = version;
            cache_covers = ladder_covers;
            cache_since = q;
            mtllib_buffer_free(full);
            event = "miss";
        }

        const uint64_t cache_bytes = cache ? mtllib_buffer_in_use(cache) : 0;
        if (cache_bytes > peak_cache) peak_cache = cache_bytes;
        fprintf(csv, "%" PRIu64 ",%zu,%zu,%" PRIu64 ",%" PRIu64 ",%s,%s,%zu,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                q, r, published, version, cached_before, event, reason, clen, full_len, delivered, vns, cache_bytes);
        mtllib_buffer_free(cond);
    }
    fclose(csv);

    char meta[4096];
    sibling_path(c.output, ".summary.json", meta, sizeof(meta));
    FILE *f = fopen(meta, "w");
    if (!f) die("cannot write %s", meta);
    const uint64_t misses = miss_cold + miss_expired + miss_uncovered + compat_fail;
    fprintf(f, "{\n");
    json_string(f, "program", "cachesim", 1);
    json_string(f, "algorithm", c.algorithm, 1);
    json_string(f, "records_source", recs.source, 1);
    json_u64(f, "initial_records", c.initial, 1);
    json_u64(f, "final_records", published, 1);
    json_u64(f, "queries", c.queries, 1);
    fprintf(f, "  \"zipf_s\": %.6g,\n", c.zipf_s);
    json_u64(f, "ttl_queries", c.ttl, 1);
    json_u64(f, "growth_every", c.growth_every, 1);
    json_u64(f, "growth_size", c.growth_size, 1);
    json_u64(f, "growth_events", events, 1);
    json_u64(f, "seed", c.seed, 1);
    json_u64(f, "hits", hits, 1);
    json_u64(f, "misses", misses, 1);
    json_u64(f, "miss_cold_start", miss_cold, 1);
    json_u64(f, "miss_expired", miss_expired, 1);
    json_u64(f, "miss_not_covered", miss_uncovered, 1);
    json_u64(f, "compat_fail", compat_fail, 1);
    json_u64(f, "hits_on_older_ladder", hits_on_old_ladder, 1);
    json_u64(f, "ladder_fetches", ladder_fetches, 1);
    json_u64(f, "ladder_signs", ladder_signs, 1);
    json_u64(f, "bytes_condensed", bytes_condensed, 1);
    json_u64(f, "bytes_full", bytes_full, 1);
    json_u64(f, "bytes_delivered", bytes_condensed + bytes_full, 1);
    json_u64(f, "peak_cache_bytes", peak_cache, 1);
    json_u64(f, "final_ladder_bytes", mtllib_buffer_in_use(ladder), 1);
    json_u64(f, "verify_hit_ns", verify_hit_ns, 1);
    json_u64(f, "verify_miss_ns", verify_miss_ns, 1);
    json_u64(f, "signer_append_ns", signer_append_ns, 1);
    json_u64(f, "signer_ladder_ns", signer_ladder_ns, 1);
    json_environment(f);
    json_u64(f, "wall_time_ns", now_ns() - started, 0);
    fprintf(f, "}\n");
    fclose(f);

    fprintf(stderr, "cachesim: Q=%" PRIu64 " hits=%" PRIu64 " misses=%" PRIu64 " compat_fail=%" PRIu64 " -> %s\n",
            c.queries, hits, misses, compat_fail, c.output);

    for (size_t i = 0; i < published; i++) {
        mtllib_sign_free_handle(&h[i]);
        mtllib_buffer_free(msg[i]);
    }
    if (cache) mtllib_buffer_free(cache);
    mtllib_buffer_free(ladder);
    if (v) mtllib_key_free(v);
    mtllib_key_free(ctx);
    records_free(&recs);
    free(msg); free(h); free(rank); free(perm); free(cdf);
    return 0;
}
