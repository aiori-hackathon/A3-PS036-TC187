/*
 * bench: per-record and batch signing/verification benchmark for PS-036.
 *
 * Three arms over the same records:
 *
 *   plain  Arm A. Plain SLH-DSA via liboqs: one zone key, one signature per
 *          record, no MTL. This is the "without MTL" workload.
 *   mtl1   Arm B. MTL mode with a batch of one: every record gets its own tree
 *          and a full MTL signature (condensed signature + signed ladder). The
 *          MTL public API cannot reset a tree, so each record needs its own key.
 *   mtl    Arm C. MTL mode with a batch of N: one key, N appends, one ladder
 *          signature, one condensed signature per record.
 *
 * Signing is always timed on the signer context. Verification is always timed
 * on a context rebuilt from the public key alone, as a resolver would hold it.
 *
 * Verification paths:
 *   cold  The verifier holds no ladder: plain verifies the SLH-DSA signature;
 *         mtl1 and mtl verify the full signature, which checks the ladder
 *         signature and then the authentication path.
 *   warm  mtl only. The ladder is verified once per batch (ladder_verify_ns),
 *         then each record is checked against it (verify_warm_ns): path hashing
 *         only, no SLH-DSA operation (mtl-ref/src/mtllib.c, ladder branch of
 *         mtllib_verify_with_ctx_str). Arms A and B have no warm path.
 *
 * Output: one CSV row per (trial, record) plus <output>.meta.json. Columns that
 * describe the whole trial are repeated on every row of that trial and must be
 * counted once per trial. Empty means "not applicable to this arm".
 *
 * Timing is CLOCK_MONOTONIC around each library call. Nothing is averaged here;
 * statistics are computed by the Python analysis.
 */
#include "common.h"

typedef enum { ARM_PLAIN, ARM_MTL1, ARM_MTL } arm_t;

static const char *ARM_NAME[] = { "plain", "mtl1", "mtl" };

typedef struct {
    char        algorithm[256];
    arm_t       arm;
    int         arm_set;
    size_t      batch;        /* N */
    size_t      sample;       /* K records processed per trial (plain, mtl1); 0 = all */
    int         trials;
    int         warmups;
    int         trial_base;   /* number of the first recorded trial */
    uint64_t    seed;
    const char *records_path;
    const char *output;
} config_t;

typedef struct {
    /* per processed record */
    uint64_t *sign_ns, *verify_cold_ns, *verify_warm_ns;
    uint64_t *signature_bytes, *condensed_bytes;
    /* per trial */
    uint64_t keygen_ns, keygen_count, ladder_sign_ns, ladder_verify_ns;
    uint64_t signed_ladder_bytes, public_key_bytes;
} trial_t;

static void usage(void)
{
    fprintf(stderr,
        "usage: bench --arm {plain|mtl1|mtl} --batch-size N --trials T --output FILE.csv\n"
        "             [--records FILE] [--sample K] [--warmups W] [--trial-base B]\n"
        "             [--seed S] [--algorithm ALG]\n"
        "  --records   fixture from `python3 -m ladderlens fixtures` (default: 64-byte LCG records)\n"
        "  --sample    plain and mtl1 only: process K evenly spaced records of the N\n"
        "  --warmups   full trials run before recording (not written)\n");
    exit(2);
}

static void parse_args(int argc, char **argv, config_t *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->algorithm, sizeof(c->algorithm), "%s", LL_DEFAULT_ALG);
    c->trial_base = 1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (!v) usage();
        if      (!strcmp(a, "--algorithm"))  snprintf(c->algorithm, sizeof(c->algorithm), "%s", v);
        else if (!strcmp(a, "--batch-size")) c->batch = strtoul(v, NULL, 10);
        else if (!strcmp(a, "--sample"))     c->sample = strtoul(v, NULL, 10);
        else if (!strcmp(a, "--trials"))     c->trials = atoi(v);
        else if (!strcmp(a, "--warmups"))    c->warmups = atoi(v);
        else if (!strcmp(a, "--trial-base")) c->trial_base = atoi(v);
        else if (!strcmp(a, "--seed"))       c->seed = strtoull(v, NULL, 10);
        else if (!strcmp(a, "--records"))    c->records_path = v;
        else if (!strcmp(a, "--output"))     c->output = v;
        else if (!strcmp(a, "--arm") || !strcmp(a, "--mode")) {
            c->arm_set = 1;
            if      (!strcmp(v, "plain")) c->arm = ARM_PLAIN;
            else if (!strcmp(v, "mtl1"))  c->arm = ARM_MTL1;
            else if (!strcmp(v, "mtl"))   c->arm = ARM_MTL;
            else usage();
        } else usage();
        i++;
    }
    if (!c->arm_set || c->batch < 1 || c->batch > LL_MAX_RECORDS || c->trials < 1 ||
        c->warmups < 0 || !c->output)
        usage();
    if (c->sample && c->arm == ARM_MTL)
        die("--sample does not apply to the mtl arm: a batch must contain all N records");
    if (c->sample >= c->batch) c->sample = 0;
}

/* Indices of the records processed in a trial: all N, or K evenly spaced. */
static size_t pick_records(const config_t *c, size_t *idx)
{
    size_t k = c->sample ? c->sample : c->batch;
    for (size_t j = 0; j < k; j++)
        idx[j] = c->sample ? (size_t)((double)j * (double)c->batch / (double)k) : j;
    return k;
}

/* ------------------------------------------------------------------ */
/* Arm A: plain SLH-DSA                                               */
/* ------------------------------------------------------------------ */

static void run_plain(const char *oqs_alg, const records_t *r, const size_t *idx, size_t k, trial_t *t)
{
    OQS_SIG *s = OQS_SIG_new(oqs_alg);
    if (!s) die("liboqs does not provide %s", oqs_alg);
    uint8_t *pk = xcalloc(s->length_public_key, 1);
    uint8_t *sk = xcalloc(s->length_secret_key, 1);
    uint8_t *sig = xcalloc(s->length_signature, 1);

    uint64_t t0 = now_ns();
    if (OQS_SIG_keypair(s, pk, sk) != OQS_SUCCESS) die("OQS_SIG_keypair failed");
    t->keygen_ns = now_ns() - t0;
    t->keygen_count = 1;
    t->public_key_bytes = s->length_public_key;

    for (size_t j = 0; j < k; j++) {
        const uint8_t *m = r->data[idx[j]];
        size_t mlen = r->len[idx[j]], slen = 0;

        t0 = now_ns();
        if (OQS_SIG_sign(s, sig, &slen, m, mlen, sk) != OQS_SUCCESS) die("OQS_SIG_sign failed (record %zu)", idx[j]);
        t->sign_ns[j] = now_ns() - t0;

        t0 = now_ns();
        OQS_STATUS ok = OQS_SIG_verify(s, m, mlen, sig, slen, pk);
        t->verify_cold_ns[j] = now_ns() - t0;
        if (ok != OQS_SUCCESS) die("plain verify rejected record %zu", idx[j]);

        t->signature_bytes[j] = slen;
    }
    OQS_MEM_secure_free(sk, s->length_secret_key);
    free(pk);
    free(sig);
    OQS_SIG_free(s);
}

/* ------------------------------------------------------------------ */
/* Arm B: MTL, one tree per record                                    */
/* ------------------------------------------------------------------ */

static void run_mtl1(char *alg, const records_t *r, const size_t *idx, size_t k, trial_t *t)
{
    t->keygen_count = k;
    for (size_t j = 0; j < k; j++) {
        MTLLIB_BUFFER *msg = buf_copy(r->data[idx[j]], r->len[idx[j]]);
        MTLLIB_CTX *ctx = NULL;
        MTL_HANDLE *h = NULL;

        uint64_t t0 = now_ns();
        if (mtllib_key_new(alg, &ctx) != MTLLIB_OK || !ctx) die("mtllib_key_new failed");
        t->keygen_ns += now_ns() - t0;
        if (j == 0) t->public_key_bytes = pubkey_bytes(ctx);

        t0 = now_ns();
        if (mtllib_sign_append(ctx, msg, &h) != MTLLIB_OK) die("mtllib_sign_append failed (record %zu)", idx[j]);
        MTLLIB_BUFFER *full = buf_new(mtllib_sign_get_full_sig_length(ctx, h));
        if (mtllib_sign_get_full_sig(ctx, h, full) != MTLLIB_OK) die("mtllib_sign_get_full_sig failed (record %zu)", idx[j]);
        t->sign_ns[j] = now_ns() - t0;

        MTLLIB_CTX *v = verifier_from(ctx, alg, full);
        size_t cond = 0;
        t0 = now_ns();
        MTLLIB_STATUS st = mtllib_verify(v, msg, full, NULL, &cond);
        t->verify_cold_ns[j] = now_ns() - t0;
        if (!verify_ok(st)) die("mtl1 verify rejected record %zu (status %d)", idx[j], (int)st);

        t->signature_bytes[j] = mtllib_buffer_in_use(full);
        t->condensed_bytes[j] = cond;
        t->signed_ladder_bytes = t->signature_bytes[j] - cond;

        mtllib_buffer_free(full);
        mtllib_sign_free_handle(&h);
        mtllib_key_free(v);
        mtllib_key_free(ctx);
        mtllib_buffer_free(msg);
    }
}

/* ------------------------------------------------------------------ */
/* Arm C: MTL, one tree for the batch                                 */
/* ------------------------------------------------------------------ */

static void run_mtl(char *alg, const records_t *r, size_t n, trial_t *t)
{
    MTLLIB_BUFFER **msg  = xcalloc(n, sizeof(*msg));
    MTLLIB_BUFFER **cond = xcalloc(n, sizeof(*cond));
    MTL_HANDLE    **h    = xcalloc(n, sizeof(*h));
    MTLLIB_CTX *ctx = NULL;

    uint64_t t0 = now_ns();
    if (mtllib_key_new(alg, &ctx) != MTLLIB_OK || !ctx) die("mtllib_key_new failed");
    t->keygen_ns = now_ns() - t0;
    t->keygen_count = 1;
    t->public_key_bytes = pubkey_bytes(ctx);

    /* Append every record. The first append on a new tree includes one-time
     * allocation; it stays in the per-record figure for record 0 and in the
     * batch total. */
    for (size_t i = 0; i < n; i++) {
        msg[i] = buf_copy(r->data[i], r->len[i]);
        t0 = now_ns();
        if (mtllib_sign_append(ctx, msg[i], &h[i]) != MTLLIB_OK) die("mtllib_sign_append failed (record %zu)", i);
        t->sign_ns[i] = now_ns() - t0;
    }

    /* One SLH-DSA signature over the ladder for the whole batch. */
    MTLLIB_BUFFER *ladder = buf_new(mtllib_sign_get_signed_ladder_length(ctx));
    t0 = now_ns();
    if (mtllib_sign_get_signed_ladder(ctx, ladder) != MTLLIB_OK) die("mtllib_sign_get_signed_ladder failed");
    t->ladder_sign_ns = now_ns() - t0;
    t->signed_ladder_bytes = mtllib_buffer_in_use(ladder);

    /* Condensed signature (randomizer + authentication path) per record. */
    for (size_t i = 0; i < n; i++) {
        cond[i] = buf_new(mtllib_sign_get_condensed_sig_length(ctx, h[i]));
        t0 = now_ns();
        if (mtllib_sign_get_condensed_sig(ctx, h[i], cond[i]) != MTLLIB_OK)
            die("mtllib_sign_get_condensed_sig failed (record %zu)", i);
        t->sign_ns[i] += now_ns() - t0;
        t->condensed_bytes[i] = mtllib_buffer_in_use(cond[i]);
        t->signature_bytes[i] = t->condensed_bytes[i] + t->signed_ladder_bytes;
    }

    MTLLIB_CTX *v = verifier_from(ctx, alg, cond[0]);

    /* Cold: full signature, ladder checked on every record. */
    for (size_t i = 0; i < n; i++) {
        MTLLIB_BUFFER *full = buf_concat(cond[i], ladder);
        size_t clen = 0;
        t0 = now_ns();
        MTLLIB_STATUS st = mtllib_verify(v, msg[i], full, NULL, &clen);
        t->verify_cold_ns[i] = now_ns() - t0;
        if (!verify_ok(st)) die("mtl cold verify rejected record %zu (status %d)", i, (int)st);
        if (clen != t->condensed_bytes[i]) die("mtl cold verify: condensed length mismatch (record %zu)", i);
        mtllib_buffer_free(full);
    }

    /* Warm: ladder checked once, then path-only verification per record. */
    t0 = now_ns();
    MTLLIB_STATUS st = mtllib_verify_signed_ladder(v, ladder);
    t->ladder_verify_ns = now_ns() - t0;
    if (st != MTLLIB_OK) die("mtllib_verify_signed_ladder rejected the ladder (status %d)", (int)st);
    for (size_t i = 0; i < n; i++) {
        size_t clen = 0;
        t0 = now_ns();
        st = mtllib_verify(v, msg[i], cond[i], ladder, &clen);
        t->verify_warm_ns[i] = now_ns() - t0;
        if (st != MTLLIB_OK) die("mtl warm verify rejected record %zu (status %d)", i, (int)st);
    }

    for (size_t i = 0; i < n; i++) {
        mtllib_sign_free_handle(&h[i]);
        mtllib_buffer_free(msg[i]);
        mtllib_buffer_free(cond[i]);
    }
    mtllib_buffer_free(ladder);
    mtllib_key_free(v);
    mtllib_key_free(ctx);
    free(msg);
    free(cond);
    free(h);
}

/* One untimed sign and verify before any measurement, so that lazy library
 * initialisation (OpenSSL digest fetch, page faults) is not charged to the
 * first recorded operation. */
static void process_warmup(const config_t *c, const char *oqs_alg, const records_t *r)
{
    size_t idx = 0;
    trial_t t;
    memset(&t, 0, sizeof(t));
    uint64_t a[1], b[1], d[1], e[1], f[1];
    t.sign_ns = a; t.verify_cold_ns = b; t.verify_warm_ns = d;
    t.signature_bytes = e; t.condensed_bytes = f;
    if (c->arm == ARM_PLAIN) run_plain(oqs_alg, r, &idx, 1, &t);
    else                     run_mtl1((char *)c->algorithm, r, &idx, 1, &t);
}

/* ------------------------------------------------------------------ */

#define CSV_COLUMNS \
    "trial,arm,batch_size,processed,record_index,record_len,seed,algorithm," \
    "keygen_count,keygen_ns,sign_ns,ladder_sign_ns,verify_cold_ns,ladder_verify_ns,verify_warm_ns," \
    "signature_bytes,condensed_bytes,signed_ladder_bytes,public_key_bytes"

static void csv_opt(FILE *f, int present, uint64_t v)
{
    if (present) fprintf(f, ",%" PRIu64, v);
    else         fputc(',', f);
}

int main(int argc, char **argv)
{
    config_t c;
    parse_args(argc, argv, &c);
    const uint64_t started = now_ns();

    MTL_ALGORITHM_PROPS *props = mtllib_util_get_algorithm_props(c.algorithm);
    if (!props || props->library != LIBOQS) die("unsupported MTL algorithm: %s", c.algorithm);
    const char *oqs_alg = props->scheme_str;

    records_t recs;
    if (c.records_path) records_load(c.records_path, c.batch, &recs);
    else                records_lcg(c.seed, c.batch, &recs);

    size_t *idx = xcalloc(c.batch, sizeof(size_t));
    const size_t k = (c.arm == ARM_MTL) ? c.batch : pick_records(&c, idx);
    if (c.arm == ARM_MTL)
        for (size_t i = 0; i < c.batch; i++) idx[i] = i;

    process_warmup(&c, oqs_alg, &recs);

    mkdirs_for(c.output);
    FILE *csv = fopen(c.output, "w");
    if (!csv) die("cannot write %s: %s", c.output, strerror(errno));
    fprintf(csv,
        "# LadderLens bench. One row per (trial, record); empty = not applicable to this arm.\n"
        "# Per trial (repeated on each row, count once): keygen_count, keygen_ns, ladder_sign_ns,\n"
        "#   ladder_verify_ns, signed_ladder_bytes, public_key_bytes.\n"
        "# Per record: sign_ns, verify_cold_ns, verify_warm_ns, signature_bytes, condensed_bytes.\n"
        CSV_COLUMNS "\n");

    trial_t t;
    for (int trial = 1; trial <= c.warmups + c.trials; trial++) {
        memset(&t, 0, sizeof(t));
        t.sign_ns = xcalloc(k, sizeof(uint64_t));
        t.verify_cold_ns = xcalloc(k, sizeof(uint64_t));
        t.verify_warm_ns = xcalloc(k, sizeof(uint64_t));
        t.signature_bytes = xcalloc(k, sizeof(uint64_t));
        t.condensed_bytes = xcalloc(k, sizeof(uint64_t));

        if      (c.arm == ARM_PLAIN) run_plain(oqs_alg, &recs, idx, k, &t);
        else if (c.arm == ARM_MTL1)  run_mtl1(c.algorithm, &recs, idx, k, &t);
        else                         run_mtl(c.algorithm, &recs, c.batch, &t);

        if (trial > c.warmups) {
            const int recorded = c.trial_base + (trial - c.warmups - 1);
            const int is_mtl = (c.arm == ARM_MTL), is_plain = (c.arm == ARM_PLAIN);
            for (size_t j = 0; j < k; j++) {
                fprintf(csv, "%d,%s,%zu,%zu,%zu,%zu,%" PRIu64 ",%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64,
                        recorded, ARM_NAME[c.arm], c.batch, k, idx[j], recs.len[idx[j]], c.seed,
                        c.algorithm, t.keygen_count, t.keygen_ns, t.sign_ns[j]);
                csv_opt(csv, is_mtl, t.ladder_sign_ns);
                fprintf(csv, ",%" PRIu64, t.verify_cold_ns[j]);
                csv_opt(csv, is_mtl, t.ladder_verify_ns);
                csv_opt(csv, is_mtl, t.verify_warm_ns[j]);
                fprintf(csv, ",%" PRIu64, t.signature_bytes[j]);
                csv_opt(csv, !is_plain, t.condensed_bytes[j]);
                csv_opt(csv, !is_plain, t.signed_ladder_bytes);
                fprintf(csv, ",%" PRIu64 "\n", t.public_key_bytes);
            }
        }
        free(t.sign_ns); free(t.verify_cold_ns); free(t.verify_warm_ns);
        free(t.signature_bytes); free(t.condensed_bytes);
    }
    fclose(csv);

    size_t min_len = SIZE_MAX, max_len = 0;
    for (size_t i = 0; i < recs.count; i++) {
        if (recs.len[i] < min_len) min_len = recs.len[i];
        if (recs.len[i] > max_len) max_len = recs.len[i];
    }

    char meta[4096];
    sibling_path(c.output, ".meta.json", meta, sizeof(meta));
    FILE *f = fopen(meta, "w");
    if (!f) die("cannot write %s", meta);
    fprintf(f, "{\n");
    json_string(f, "program", "bench", 1);
    json_string(f, "arm", ARM_NAME[c.arm], 1);
    json_string(f, "algorithm", c.algorithm, 1);
    json_string(f, "oqs_algorithm", oqs_alg, 1);
    json_u64(f, "batch_size", c.batch, 1);
    json_u64(f, "processed", k, 1);
    json_u64(f, "trials", (uint64_t)c.trials, 1);
    json_u64(f, "warmups", (uint64_t)c.warmups, 1);
    json_u64(f, "trial_base", (uint64_t)c.trial_base, 1);
    json_u64(f, "seed", c.seed, 1);
    json_string(f, "records_source", recs.source, 1);
    json_u64(f, "record_len_min", min_len, 1);
    json_u64(f, "record_len_max", max_len, 1);
    json_environment(f);
    json_u64(f, "wall_time_ns", now_ns() - started, 0);
    fprintf(f, "}\n");
    fclose(f);

    fprintf(stderr, "bench: %s N=%zu processed=%zu trials=%d -> %s\n",
            ARM_NAME[c.arm], c.batch, k, c.trials, c.output);
    records_free(&recs);
    free(idx);
    return 0;
}
