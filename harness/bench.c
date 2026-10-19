/*
 * LadderLens 1B — C benchmark harness: MTL (batch) vs per-record (non-MTL) PQC signing.
 *
 * Build:  make harness   (compiles harness/bench INSIDE the pinned container; links
 *           -lmtllib -loqs -lcrypto). Run via `make harness-run ARGS=... OUTPUT=...`.
 *
 * Links libmtl directly (installed in the pinned image). ALL MTL API calls go through
 * the PUBLIC C API declared in mtl-ref/src/mtllib.h and implemented in mtl-ref/src/mtllib.c
 * (cited at each call site below: file:line + function). No internal APIs are used.
 *
 * Timing: CLOCK_MONOTONIC via clock_gettime(2), nanosecond resolution. Raw per-trial
 * rows only — NO averaging or statistics inside this program (analysis is done in
 * Python, phase 1C).
 *
 * Output:
 *   - CSV:     one row per trial per record (schema documented below).
 *   - Metadata: <output>.meta.json (env + pin metadata + algorithm sizes).
 *
 * Records: RECORD_SIZE = 64 bytes each, deterministic from --seed via a NON-cryptographic
 *   LCG. 64 B approximates the variable-length RDATA of a short DNS record; it is a
 *   CHOSEN workload size, not a measured DNS size.
 *
 * MODES
 *   mtl    : one key; append N records; sign the ladder ONCE; extract a condensed
 *            signature per record.
 *   nonmtl : sign each of the N records separately as an independent batch-of-1
 *            (append + full signature per record).
 *
 * NON-MTL OVERESTIMATE (documented; see PROGRESS.md 1B notes):
 *   The MTL public API has no "reset the tree of one MTLLIB_CTX" and no "sign a raw
 *   message with an existing key" — the tree inside an MTLLIB_CTX only GROWS as records
 *   are appended (mtl_hash_and_append, mtl-ref/src/mtl.c) — so true per-record signing
 *   with ONE zone key cannot be expressed. Instead, non-MTL mode creates one MTLLIB_CTX
 *   per record via mtllib_key_new (mtl-ref/src/mtllib.h:142), i.e. N keypairs.
 *   Consequences:
 *     - keygen_time_ns is reported SEPARATELY and is an overestimate for non-MTL
 *       (N keygens vs 1 for MTL). It is never folded into sign comparisons.
 *     - sign_time_ns excludes keygen: non-MTL = append + full-sig extraction per record;
 *       MTL = append + condensed extraction per record (+ ladder sign as batch column).
 *     - The central finding (MTL amortises ONE OQS ladder signature across N records;
 *       non-MTL pays N OQS signatures) holds regardless of the overestimate.
 *
 * COLD vs WARM VERIFICATION (documented; semantics verified against mtl-ref/src/mtllib.c):
 *   cold  : verify each record from its FULL signature (condensed || ladder) with NO
 *           pre-verified ladder — mtllib_verify (mtllib.h:293, impl mtllib.c:855) runs
 *           the full-sig path: OQS-verifies the ladder signature, then the auth path.
 *           Paid PER RECORD in cold mode.
 *   warm  : pre-validate the ladder ONCE per key via mtllib_verify_signed_ladder
 *           (mtllib.h:322, impl mtllib.c:1059) — the OQS ladder-signature check — then
 *           verify each record's condensed signature against that (trusted) ladder via
 *           mtllib_verify(ctx, msg, cond, ladder_buf, &len): parse + auth path only, NO
 *           OQS call per record (mtllib.c:935 path). The library does NOT cache a parsed
 *           ladder across calls, so the per-record warm cost includes ladder re-parsing;
 *           what warm saves is the PER-RECORD OQS ladder-signature verification.
 *
 * CSV SCHEMA — one row per trial per record. Why per record: sign and verify times are
 * per-record events; batch-level quantities are REPEATED on every row of a trial and
 * must be counted ONCE per trial (from record_index 0), NOT summed over rows.
 *   1  trial                     int
 *   2  mode                      string  nonmtl | mtl
 *   3  record_index              int     0-based
 *   4  seed                      uint64
 *   5  batch_size                int     (= N)
 *   6  algorithm                 string
 *   7  keygen_time_ns            uint64  BATCH (mtl: 1 keygen; nonmtl: N keygens). REPEATED.
 *   8  sign_time_ns              uint64  PER-RECORD, EXCLUDES keygen.
 *                                        mtl:    append_i + condensed_i.
 *                                        nonmtl: append_i + full_sig_i (the 1-leaf-ladder
 *                                                OQS sign is inside this).
 *   9  ladder_sign_time_ns       uint64  BATCH (mtl: the single get_signed_ladder call;
 *                                        nonmtl: 0 — its 1-leaf OQS signs are inside
 *                                        sign_time_ns). REPEATED; count ONCE per trial.
 *  10  verify_time_cold_ns       uint64  PER-RECORD mtllib_verify(full_sig, NULL).
 *  11  ladder_verify_time_ns_warm uint64 BATCH upfront OQS ladder verification for the
 *                                        warm path (mtl: 1× verify_signed_ladder(N-leaf);
 *                                        nonmtl: SUM of N× verify_signed_ladder(1-leaf)).
 *                                        REPEATED; count ONCE per trial.
 *  12  verify_time_warm_ns       uint64  PER-RECORD warm verify = parse + auth path ONLY
 *                                        (same definition in both modes).
 *  13  bytes_full_signature      uint64  PER-RECORD full signature size.
 *  14  bytes_condensed_signature uint64  PER-RECORD condensed signature size.
 *  15  bytes_condensed_min       uint64  BATCH min over records. REPEATED.
 *  16  bytes_condensed_mean      uint64  BATCH mean (integer, floor). REPEATED.
 *  17  bytes_condensed_max       uint64  BATCH max. REPEATED.
 *  18  bytes_signed_ladder       uint64  BATCH ladder size (mtl: N-leaf ladder; nonmtl:
 *                                        the 1-leaf ladder, identical for all records).
 *                                        REPEATED; count ONCE per trial.
 *  19  bytes_public_key          uint64  BATCH public-key size. REPEATED.
 *
 * Trial totals (how 1C should aggregate):
 *   mtl    sign  = keygen_time_ns + ladder_sign_time_ns + SUM(sign_time_ns)
 *   nonmtl sign  = keygen_time_ns + SUM(sign_time_ns)
 *   any    cold  = SUM(verify_time_cold_ns)
 *   any    warm  = ladder_verify_time_ns_warm + SUM(verify_time_warm_ns)
 *
 * Warm-up trials are fully executed but NOT written to the CSV.
 *
 * Every API return code is checked; any failure or verification mismatch exits non-zero
 * with a message on stderr (fail loudly).
 */

#include <mtllib.h>              /* ALL public MTL API (mtl-ref/src/mtllib.h) */
#include <oqs/common.h>          /* OQS_version() */
#include <openssl/crypto.h>      /* OpenSSL_version() */
#include <time.h>                /* clock_gettime, CLOCK_MONOTONIC */
#include <sys/utsname.h>         /* uname (kernel release) */
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#ifndef HARNESS_COMMIT
#define HARNESS_COMMIT unknown
#endif
/* Two-level stringify: -DHARNESS_COMMIT=1e04598 arrives as a bare token, so it
 * must be stringified here (CI run #6: 'd8e8f4c' undeclared). STR_(x) #x alone
 * would stringify the literal name HARNESS_COMMIT; the extra level makes the
 * preprocessor expand it first. */
#define STR_(x) #x
#define STR(x) STR_(x)

#define RECORD_SIZE 64           /* bytes per record (chosen workload size, documented) */
#define MAX_RECORDS 2048         /* safety cap on --batch-size */

/* ------------------------------------------------------------------ */
/*  Timing: CLOCK_MONOTONIC, nanosecond resolution                     */
/* ------------------------------------------------------------------ */

static inline void ts_start(struct timespec *s)
{
    if (clock_gettime(CLOCK_MONOTONIC, s) != 0) {
        perror("clock_gettime(CLOCK_MONOTONIC)");
        exit(1);
    }
}

static inline uint64_t elapsed_ns(const struct timespec *start)
{
    struct timespec e;
    if (clock_gettime(CLOCK_MONOTONIC, &e) != 0) {
        perror("clock_gettime(CLOCK_MONOTONIC)");
        exit(1);
    }
    return (uint64_t)(e.tv_sec - start->tv_sec) * 1000000000ULL
         + (uint64_t)(e.tv_nsec - start->tv_nsec);
}

/* MTLLIB_OK == 0 (mtl-ref/src/mtllib_status.h:43); mtllib_verify also returns
 * MTLLIB_OK_VALIDATED_LADDER == 1 (mtllib_status.h:46) on the full-sig path
 * (mtl-ref/src/mtllib.c:855). Both mean success. */
static int verify_ok(MTLLIB_STATUS s)
{
    return s == MTLLIB_OK || s == MTLLIB_OK_VALIDATED_LADDER;
}

static void die(const char *msg)
{
    fprintf(stderr, "FATAL: %s\n", msg);
    exit(1);
}

/* ------------------------------------------------------------------ */
/*  Deterministic records (NON-cryptographic LCG; content not hashed)  */
/* ------------------------------------------------------------------ */

static void gen_records(uint64_t seed, int n, uint8_t records[][RECORD_SIZE])
{
    uint64_t x = seed ? seed : 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < RECORD_SIZE; j++) {
            x = x * 6364136223846793005ULL + 1442695040888963407ULL;
            records[i][j] = (uint8_t)(x >> 33);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  MTLLIB_BUFFER helpers (mtl-ref/src/mtllib_buffer.h)                */
/*  Convention: all output sig buffers are pre-initialized with the    */
/*  exact capacity from the corresponding *_length() API, then the     */
/*  library APPENDS into them (see mtllib_sign_get_full_sig impl,      */
/*  mtl-ref/src/mtllib.c, which uses the same pattern).                */
/* ------------------------------------------------------------------ */

static MTLLIB_BUFFER *new_buf(size_t capacity, const char *what)
{
    MTLLIB_BUFFER *b = NULL;
    /* mtllib_buffer_initialize (mtllib_buffer.h:72, impl mtllib_buffer.c:48):
     * data==NULL => internal allocation owned by the buffer. */
    if (mtllib_buffer_initialize(&b, capacity, NULL) != MTLLIB_OK || b == NULL) {
        fprintf(stderr, "FATAL: mtllib_buffer_initialize failed for %s\n", what);
        exit(1);
    }
    return b;
}

static void free_buf(MTLLIB_BUFFER *b)
{
    if (b) {
        /* frees internal data AND the struct (mtllib_buffer.c:85).
         * External (caller-referenced) data is NOT freed — by design. */
        mtllib_buffer_free(b);
    }
}

/* Trial/record context for FATAL diagnostics (single-threaded harness).
 * g_record is -1 outside per-record loops. */
static int         g_trial  = -1;
static int         g_record = -1;
static const char *g_warm   = "?";

/* FATAL naming the exact pointer if NULL; called before every MTL call so a
 * future failure says where it happened (added after CI run #7). */
static void require_ptr(const char *name, const void *p)
{
    if (p == NULL) {
        fprintf(stderr, "FATAL: NULL pointer: %s (trial %d, record %d, %s)\n",
                name, g_trial, g_record, g_warm);
        exit(1);
    }
}

/* For an MTLLIB_BUFFER that must already CONTAIN bytes: in_use > 0 and a valid
 * data pointer. Catches the empty-internal-buffer case that made
 * mtllib_sign_append pass message_len==0 into mtl_hash_and_append
 * (mtl-ref/src/mtl_abstract.c:129 "NULL Input Pointers", CI run #7):
 * mtllib_buffer_initialize(data=NULL) sets buffer_position=0
 * (mtllib_buffer.c:60-69) — bytes must be added with mtllib_buffer_append
 * (mtllib_buffer.c), which advances position, not with a raw memcpy. */
static void require_buf_data(const char *name, MTLLIB_BUFFER *b)
{
    require_ptr(name, (const void *)b);
    if (mtllib_buffer_data_ptr(b) == NULL || mtllib_buffer_in_use(b) == 0) {
        fprintf(stderr, "FATAL: buffer has no data: %s (in_use=%zu, trial %d, record %d, %s)\n",
                name, mtllib_buffer_in_use(b), g_trial, g_record, g_warm);
        exit(1);
    }
}

/* ------------------------------------------------------------------ */
/*  FS / env helpers                                                   */
/* ------------------------------------------------------------------ */

static int mkdirs(const char *path)
{
    char tmp[4096];
    if (!path || !*path) return 0;
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return 0;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static void dir_of(const char *path, char *out, size_t outn)
{
    const char *slash = strrchr(path, '/');
    if (!slash) snprintf(out, outn, ".");
    else if (slash == path) snprintf(out, outn, "/");
    else snprintf(out, outn, "%.*s", (int)(slash - path), path);
}

static void json_escape(const char *in, char *out, size_t outn)
{
    size_t o = 0;
    for (const char *p = in; *p && o + 6 < outn; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            out[o++] = '\\'; out[o++] = (char)c;
        } else if (c < 0x20) {
            o += (size_t)snprintf(out + o, outn - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

static void read_cpu_model(char *out, size_t outn)
{
    snprintf(out, outn, "unknown");
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "model name", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                colon++;
                while (*colon == ' ' || *colon == '\t') colon++;
                size_t l = strlen(colon);
                while (l > 0 && (colon[l - 1] == '\n' || colon[l - 1] == '\r')) colon[--l] = '\0';
                snprintf(out, outn, "%s", colon);
            }
            break;
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/*  CLI                                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    char     algorithm[256];
    int      batch_size;   /* N */
    int      trials;       /* T (recorded) */
    int      warmups;      /* W (executed, not recorded) */
    uint64_t seed;
    int      mode;         /* 0 = nonmtl, 1 = mtl */
    char     output[4096];
} config_t;

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s --algorithm ALG --batch-size N --trials T --warmups W\n"
        "          --seed S --mode {nonmtl|mtl} --output path.csv\n"
        "  ALG   e.g. SLH-DSA-SHA2-128s-MTL-SHA2-128\n"
        "  N     records per trial (1..%d)\n"
        "  T     recorded trials; W warm-up trials are run but NOT recorded\n"
        "  S     seed for the deterministic record generator\n",
        prog, MAX_RECORDS);
    exit(2);
}

static int parse_args(int argc, char **argv, config_t *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->algorithm, sizeof(c->algorithm), "SLH-DSA-SHA2-128s-MTL-SHA2-128");
    c->batch_size = -1; c->trials = -1; c->warmups = -1; c->seed = 0; c->mode = -1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT_ARG() (i + 1 < argc ? argv[++i] : NULL)
        if (strcmp(a, "--algorithm") == 0) {
            const char *v = NEXT_ARG(); if (!v) usage(argv[0]);
            snprintf(c->algorithm, sizeof(c->algorithm), "%s", v);
        } else if (strcmp(a, "--batch-size") == 0) {
            const char *v = NEXT_ARG(); if (!v) usage(argv[0]);
            c->batch_size = atoi(v);
        } else if (strcmp(a, "--trials") == 0) {
            const char *v = NEXT_ARG(); if (!v) usage(argv[0]);
            c->trials = atoi(v);
        } else if (strcmp(a, "--warmups") == 0) {
            const char *v = NEXT_ARG(); if (!v) usage(argv[0]);
            c->warmups = atoi(v);
        } else if (strcmp(a, "--seed") == 0) {
            const char *v = NEXT_ARG(); if (!v) usage(argv[0]);
            c->seed = strtoull(v, NULL, 10);
        } else if (strcmp(a, "--mode") == 0) {
            const char *v = NEXT_ARG(); if (!v) usage(argv[0]);
            if (strcmp(v, "nonmtl") == 0) c->mode = 0;
            else if (strcmp(v, "mtl") == 0) c->mode = 1;
            else usage(argv[0]);
        } else if (strcmp(a, "--output") == 0) {
            const char *v = NEXT_ARG(); if (!v) usage(argv[0]);
            snprintf(c->output, sizeof(c->output), "%s", v);
        } else {
            fprintf(stderr, "unknown argument: %s\n", a);
            usage(argv[0]);
        }
        #undef NEXT_ARG
    }

    if (c->batch_size < 1 || c->batch_size > MAX_RECORDS ||
        c->trials < 1 || c->warmups < 0 || c->mode < 0 || c->output[0] == '\0') {
        usage(argv[0]);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Metadata                                                           */
/* ------------------------------------------------------------------ */

static void write_metadata(const char *meta_path, const config_t *cfg,
                           const char *cpu_model, const char *kernel,
                           const char *compiler,
                           uint64_t len_public_key, uint64_t len_secret_key,
                           uint64_t len_signature)
{
    FILE *f = fopen(meta_path, "w");
    if (!f) { perror("fopen metadata"); exit(1); }

    char esc[1024];
    const char *mtl_commit  = getenv("MTL_REF_COMMIT");
    const char *openssl_pin = getenv("OPENSSL_SHA");
    const char *liboqs_pin  = getenv("LIBOQS_SHA");

    json_escape(cpu_model, esc, sizeof(esc));
    fprintf(f, "{\n  \"cpu_model\": \"%s\",\n", esc);
    json_escape(kernel, esc, sizeof(esc));
    fprintf(f, "  \"kernel\": \"%s\",\n", esc);
    json_escape(compiler, esc, sizeof(esc));
    fprintf(f, "  \"compiler\": \"%s\",\n", esc);
    fprintf(f, "  \"openssl_version\": \"%s\",\n", OpenSSL_version(OPENSSL_VERSION));
    fprintf(f, "  \"liboqs_version\": \"%s\",\n", OQS_version());
    fprintf(f, "  \"mtl_lib_version\": \"%s\",\n", MTL_LIB_VERSION);   /* mtl-ref/src/mtl.h:41 */
    fprintf(f, "  \"mtl_ref_commit\": \"%s\",\n",  mtl_commit  ? mtl_commit  : "not-set");
    fprintf(f, "  \"openssl_sha\": \"%s\",\n",     openssl_pin ? openssl_pin : "not-set");
    fprintf(f, "  \"liboqs_sha\": \"%s\",\n",      liboqs_pin  ? liboqs_pin  : "not-set");
    fprintf(f, "  \"harness_commit\": \"%s\",\n", STR(HARNESS_COMMIT));
    json_escape(cfg->algorithm, esc, sizeof(esc));
    fprintf(f, "  \"algorithm\": \"%s\",\n", esc);
    fprintf(f, "  \"mode\": \"%s\",\n", cfg->mode == 1 ? "mtl" : "nonmtl");
    fprintf(f, "  \"batch_size\": %d,\n", cfg->batch_size);
    fprintf(f, "  \"trials\": %d,\n", cfg->trials);
    fprintf(f, "  \"warmups\": %d,\n", cfg->warmups);
    fprintf(f, "  \"seed\": %" PRIu64 ",\n", cfg->seed);
    fprintf(f, "  \"record_size\": %d,\n", RECORD_SIZE);
    fprintf(f, "  \"clock\": \"CLOCK_MONOTONIC\",\n");
    fprintf(f, "  \"length_public_key\": %" PRIu64 ",\n", len_public_key);
    fprintf(f, "  \"length_secret_key\": %" PRIu64 ",\n", len_secret_key);
    fprintf(f, "  \"length_signature\": %" PRIu64 "\n", len_signature);
    fprintf(f, "}\n");
    fclose(f);
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    config_t cfg;
    parse_args(argc, argv, &cfg);
    const int      N    = cfg.batch_size;
    const int      T    = cfg.trials;
    const int      W    = cfg.warmups;
    const uint64_t seed = cfg.seed;
    const int      mode = cfg.mode;
    char          *alg  = cfg.algorithm;   /* mtllib_key_new takes char* (mtllib.h:142) */

    /* ---------- environment ---------- */
    char cpu_model[512], kernel[256], compiler[256];
    read_cpu_model(cpu_model, sizeof(cpu_model));
    {
        struct utsname u;
        if (uname(&u) != 0) snprintf(kernel, sizeof(kernel), "unknown");
        else                snprintf(kernel, sizeof(kernel), "%s", u.release);
    }
    snprintf(compiler, sizeof(compiler), "gcc %s", __VERSION__);

    /* ---------- output paths ---------- */
    char meta_path[4096];
    {
        size_t n = strlen(cfg.output);
        if (n > 4 && strcmp(cfg.output + n - 4, ".csv") == 0)
            snprintf(meta_path, sizeof(meta_path), "%.*s.meta.json", (int)(n - 4), cfg.output);
        else
            snprintf(meta_path, sizeof(meta_path), "%s.meta.json", cfg.output);
    }
    {
        char d[4096];
        dir_of(cfg.output, d, sizeof(d));
        if (mkdirs(d) != 0) die("mkdir of output directory failed");
    }

    /* ---------- validate algorithm + capture OQS lengths (throwaway key) ----------
     * mtllib_key_new (mtllib.h:142) fails with MTLLIB_BAD_ALGORITHM for unknown
     * algorithm strings — fail loudly here before any timing. */
    uint64_t len_public_key = 0, len_secret_key = 0, len_signature = 0;
    {
        MTLLIB_CTX *tctx = NULL;
        if (mtllib_key_new(alg, &tctx) != MTLLIB_OK || tctx == NULL) {
            fprintf(stderr, "FATAL: mtllib_key_new failed for algorithm '%s' "
                            "(unsupported by this MTL build?)\n", alg);
            return 1;
        }
        /* OQS_SIG members (mtl-ref/src/mtllib.h:85-95 struct; oqs/sig.h types) */
        len_public_key = (uint64_t)tctx->signature->length_public_key;
        len_secret_key = (uint64_t)tctx->signature->length_secret_key;
        len_signature  = (uint64_t)tctx->signature->length_signature;
        mtllib_key_free(tctx);                      /* mtllib.h:165 */
    }

    /* ---------- open CSV + header ---------- */
    FILE *csv = fopen(cfg.output, "w");
    if (!csv) { perror("fopen csv"); return 1; }
    fprintf(csv,
        "# LadderLens 1B C harness CSV - one row per trial per record.\n"
        "# Batch-level columns (keygen_time_ns, ladder_sign_time_ns,\n"
        "# ladder_verify_time_ns_warm, bytes_condensed_min/mean/max,\n"
        "# bytes_signed_ladder, bytes_public_key) are REPEATED on every row of a\n"
        "# trial; count those ONCE per trial (from record_index 0), do NOT sum rows.\n"
        "# Per-row columns (sign_time_ns, verify_time_cold_ns, verify_time_warm_ns,\n"
        "# bytes_full_signature, bytes_condensed_signature) vary per record; sum or\n"
        "# average over a trial's rows. See harness/bench.c header for semantics.\n"
        "trial,mode,record_index,seed,batch_size,algorithm,keygen_time_ns,\n"
        "sign_time_ns,ladder_sign_time_ns,verify_time_cold_ns,\n"
        "ladder_verify_time_ns_warm,verify_time_warm_ns,bytes_full_signature,\n"
        "bytes_condensed_signature,bytes_condensed_min,bytes_condensed_mean,\n"
        "bytes_condensed_max,bytes_signed_ladder,bytes_public_key\n");

    /* ---------- pre-generate records (same across all trials) ---------- */
    uint8_t (*records)[RECORD_SIZE] = calloc((size_t)N, RECORD_SIZE);
    if (!records) die("calloc records");
    gen_records(seed, N, records);

    /* ================= trial loop: W warm-ups + T recorded ================= */
    int total_rows = 0;
    for (int t = 1; t <= W + T; t++) {
        const int is_warmup = (t <= W);
        g_trial  = t;                          /* FATAL diagnostics context */
        g_warm   = is_warmup ? "warm-up" : "recorded";
        g_record = -1;

        /* ---------- keygen phase (timed separately; never part of sign) ---------- */
        uint64_t keygen_time = 0;
        MTLLIB_CTX  *ctx     = NULL;   /* mtl mode: one key */
        MTLLIB_CTX **ctx_arr = NULL;   /* nonmtl mode: N keys (see header overestimate note) */
        if (mode == 1) {
            struct timespec ks; ts_start(&ks);
            if (mtllib_key_new(alg, &ctx) != MTLLIB_OK || ctx == NULL) {
                fprintf(stderr, "FATAL: mtllib_key_new failed (trial %d)\n", t);
                return 1;
            }
            keygen_time = elapsed_ns(&ks);
        } else {
            ctx_arr = calloc((size_t)N, sizeof(MTLLIB_CTX *));
            if (!ctx_arr) die("calloc ctx_arr");
            struct timespec ks; ts_start(&ks);
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                if (mtllib_key_new(alg, &ctx_arr[i]) != MTLLIB_OK || ctx_arr[i] == NULL) {
                    fprintf(stderr, "FATAL: mtllib_key_new failed (trial %d, rec %d)\n", t, i);
                    return 1;
                }
            }
            keygen_time = elapsed_ns(&ks);
        }

        /* ---------- public-key size (measured via mtllib_pubkey_to_buffer,
         *            mtllib.h:149 + :158) ---------- */
        uint64_t pubkey_size = 0;
        {
            MTLLIB_CTX *kctx = (mode == 1) ? ctx : ctx_arr[0];
            size_t pb_len = mtllib_pubkey_to_buffer_length(kctx);
            MTLLIB_BUFFER *pb = new_buf(pb_len ? pb_len : 1, "pubkey");
            if (mtllib_pubkey_to_buffer(kctx, pb) != MTLLIB_OK) {
                fprintf(stderr, "FATAL: mtllib_pubkey_to_buffer failed (trial %d)\n", t);
                return 1;
            }
            pubkey_size = (uint64_t)mtllib_buffer_in_use(pb);   /* mtllib_buffer.h:94 */
            free_buf(pb);
        }

        /* ---------- per-record scratch ---------- */
        uint64_t *sign_time   = calloc((size_t)N, sizeof(uint64_t));
        uint64_t *v_cold      = calloc((size_t)N, sizeof(uint64_t));
        uint64_t *v_warm      = calloc((size_t)N, sizeof(uint64_t));
        uint64_t *bytes_full  = calloc((size_t)N, sizeof(uint64_t));
        uint64_t *bytes_cond  = calloc((size_t)N, sizeof(uint64_t));
        uint64_t *bytes_ladder_rec = calloc((size_t)N, sizeof(uint64_t));
        if (!sign_time || !v_cold || !v_warm || !bytes_full || !bytes_cond || !bytes_ladder_rec)
            die("calloc trial arrays");

        uint64_t ladder_sign_time       = 0;  /* batch */
        uint64_t ladder_verify_time_wrm = 0;  /* batch upfront OQS ladder verify */
        uint64_t bytes_signed_ladder    = 0;  /* batch */
        uint64_t cond_min = UINT64_MAX, cond_max = 0, cond_sum = 0;

        /* ================= SIGN PHASE ================= */
        if (mode == 1) {
            /* ----- MTL: one ctx, N appends, ONE ladder sign, N condensed ----- */
            MTL_HANDLE   **handles  = calloc((size_t)N, sizeof(MTL_HANDLE *));
            MTLLIB_BUFFER **msg     = calloc((size_t)N, sizeof(MTLLIB_BUFFER *));
            MTLLIB_BUFFER **cond    = calloc((size_t)N, sizeof(MTLLIB_BUFFER *));
            MTLLIB_BUFFER  *ladder  = NULL;
            if (!handles || !msg || !cond) die("calloc mtl arrays");

            /* (1) append each record — mtllib_sign_append (mtllib.h:211); the tree
             *     inside ctx grows; handle[i] identifies leaf i (MTL_HANDLE.leaf_index,
             *     mtllib.h:96-100). Timed per record (append only). */
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                msg[i] = new_buf(RECORD_SIZE, "msg");
                /* mtllib_buffer_append (mtllib_buffer.c) memcpy's at the current
                 * position AND advances it (buffer_position += length), so the
                 * library reads in_use()==RECORD_SIZE bytes. A raw memcpy into
                 * data_ptr left position==0 => message_len==0 => NULL-input guard
                 * in mtl_hash_and_append (mtl_abstract.c:129) — CI run #7. */
                if (mtllib_buffer_append(msg[i], records[i], RECORD_SIZE) != MTLLIB_OK) {
                    fprintf(stderr, "FATAL: mtllib_buffer_append msg[%d] failed (trial %d)\n", i, t);
                    return 1;
                }
                require_ptr("ctx", (const void *)ctx);
                require_buf_data("msg[i] (mtl append)", msg[i]);
                struct timespec st; ts_start(&st);
                if (mtllib_sign_append(ctx, msg[i], &handles[i]) != MTLLIB_OK) {
                    fprintf(stderr, "FATAL: mtllib_sign_append failed rec %d trial %d\n", i, t);
                    return 1;
                }
                sign_time[i] = elapsed_ns(&st);
            }

            /* (2) sign the ladder ONCE — mtllib_sign_get_signed_ladder (mtllib.h:265,
             *     impl mtllib.c:726): builds the N-leaf ladder (mtl_ladder, mtl.c) and
             *     makes the SINGLE OQS signature over it. Timed as a BATCH event. */
            {
                size_t cap = mtllib_sign_get_signed_ladder_length(ctx);   /* mtllib.h:256 */
                ladder = new_buf(cap, "ladder");
                struct timespec st; ts_start(&st);
                if (mtllib_sign_get_signed_ladder(ctx, ladder) != MTLLIB_OK) {
                    fprintf(stderr, "FATAL: mtllib_sign_get_signed_ladder failed (trial %d)\n", t);
                    return 1;
                }
                ladder_sign_time    = elapsed_ns(&st);
                bytes_signed_ladder = (uint64_t)mtllib_buffer_in_use(ladder);
            }

            /* (3) condensed signature per record — mtllib_sign_get_condensed_sig
             *     (mtllib.h:249, impl mtllib.c:~790): randomizer + auth path for
             *     leaf i. Timed per record; ADDED to that record's append time. */
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                require_ptr("handles[i] (get_condensed_sig)", (const void *)handles[i]);
                size_t cap = mtllib_sign_get_condensed_sig_length(ctx, handles[i]);  /* mtllib.h:239 */
                cond[i] = new_buf(cap, "condensed");
                /* Guard goes AFTER new_buf: in CI run #9 the pre-init check fired
                 * on the calloc-zeroed slot before allocation. */
                require_ptr("cond[i] (output buffer, after new_buf)", (const void *)cond[i]);
                struct timespec st; ts_start(&st);
                if (mtllib_sign_get_condensed_sig(ctx, handles[i], cond[i]) != MTLLIB_OK) {
                    fprintf(stderr, "FATAL: mtllib_sign_get_condensed_sig failed rec %d trial %d\n", i, t);
                    return 1;
                }
                sign_time[i] += elapsed_ns(&st);

                bytes_cond[i] = (uint64_t)mtllib_buffer_in_use(cond[i]);
                bytes_full[i] = bytes_cond[i] + bytes_signed_ladder;
                if (bytes_cond[i] < cond_min) cond_min = bytes_cond[i];
                if (bytes_cond[i] > cond_max) cond_max = bytes_cond[i];
                cond_sum += bytes_cond[i];
            }

            /* ---------- COLD verify per record (full sig, no pre-verified ladder).
             * mtllib_verify (mtllib.h:293, impl mtllib.c:855) full-sig path: parses the
             * ladder from the sig, OQS-verifies the ladder signature, verifies the
             * auth path — the OQS ladder check is paid PER RECORD. Concatenation is
             * NOT timed. Returns MTLLIB_OK_VALIDATED_LADDER on this path. */
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                MTLLIB_BUFFER *fs = new_buf(bytes_full[i], "full_sig_cold");
                if (mtllib_buffer_append(fs, mtllib_buffer_data_ptr(cond[i]),  /* mtllib_buffer.h:117 */
                                         bytes_cond[i]) != MTLLIB_OK) die("append cond->full");
                if (mtllib_buffer_append(fs, mtllib_buffer_data_ptr(ladder),
                                         bytes_signed_ladder) != MTLLIB_OK) die("append ladder->full");
                require_buf_data("msg[i] (mtl cold verify)", msg[i]);
                require_buf_data("fs (mtl cold verify)", fs);
                size_t condensed_len = 0;
                struct timespec vt; ts_start(&vt);
                MTLLIB_STATUS r = mtllib_verify(ctx, msg[i], fs, NULL, &condensed_len);
                v_cold[i] = elapsed_ns(&vt);
                if (!verify_ok(r)) {
                    fprintf(stderr, "FATAL: cold verify FAILED rec %d trial %d (status %d)\n",
                            i, t, (int)r);
                    return 1;
                }
                if ((uint64_t)condensed_len != bytes_cond[i]) {
                    fprintf(stderr, "FATAL: cold verify condensed_len %zu != condensed size %" PRIu64
                            " rec %d trial %d\n", condensed_len, bytes_cond[i], i, t);
                    return 1;
                }
                free_buf(fs);
            }

            /* ---------- WARM verify: upfront ladder check ONCE (batch) via
             * mtllib_verify_signed_ladder (mtllib.h:322, impl mtllib.c:1059 — OQS
             * verify of the ladder signature), then per-record condensed verifies
             * against the trusted ladder (mtllib_verify ladder path, mtllib.c:935:
             * parse + auth path, NO OQS call). */
            {
                require_buf_data("ladder (verify_signed_ladder)", ladder);
                struct timespec vt; ts_start(&vt);
                MTLLIB_STATUS r = mtllib_verify_signed_ladder(ctx, ladder);
                ladder_verify_time_wrm = elapsed_ns(&vt);
                if (r != MTLLIB_OK) {
                    fprintf(stderr, "FATAL: mtllib_verify_signed_ladder FAILED trial %d (status %d)\n",
                            t, (int)r);
                    return 1;
                }
            }
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                require_buf_data("msg[i] (mtl warm verify)", msg[i]);
                require_buf_data("cond[i] (mtl warm verify)", cond[i]);
                require_buf_data("ladder (mtl warm verify)", ladder);
                size_t condensed_len = 0;
                struct timespec vt; ts_start(&vt);
                MTLLIB_STATUS r = mtllib_verify(ctx, msg[i], cond[i], ladder, &condensed_len);
                v_warm[i] = elapsed_ns(&vt);
                if (!verify_ok(r)) {
                    fprintf(stderr, "FATAL: warm verify FAILED rec %d trial %d (status %d)\n",
                            i, t, (int)r);
                    return 1;
                }
                if ((uint64_t)condensed_len != bytes_cond[i]) {
                    fprintf(stderr, "FATAL: warm verify condensed_len mismatch rec %d trial %d\n", i, t);
                    return 1;
                }
            }

            /* ---------- cleanup trial (mtl) ---------- */
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                mtllib_sign_free_handle(&handles[i]);   /* mtllib.h:232 */
                free_buf(msg[i]);
                free_buf(cond[i]);
            }
            free(handles); free(msg); free(cond);
            free_buf(ladder);
            mtllib_key_free(ctx);                       /* mtllib.h:165 */
        } else {
            /* ----- NON-MTL: one independent key + batch-of-1 sign per record ----- */
            MTL_HANDLE   **handles  = calloc((size_t)N, sizeof(MTL_HANDLE *));
            MTLLIB_BUFFER **msg     = calloc((size_t)N, sizeof(MTLLIB_BUFFER *));
            MTLLIB_BUFFER **fs      = calloc((size_t)N, sizeof(MTLLIB_BUFFER *));
            uint64_t      *cond_len = calloc((size_t)N, sizeof(uint64_t));
            if (!handles || !msg || !fs || !cond_len) die("calloc nonmtl arrays");

            /* (1) per record: append + full signature. mtllib_sign_get_full_sig
             * (mtllib.h:282, impl mtllib.c) = condensed + 1-leaf signed ladder; the
             * OQS sign of the 1-leaf ladder happens INSIDE this call, so it is part
             * of sign_time_ns (documented in the header; ladder_sign_time_ns = 0). */
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                MTLLIB_CTX *c = ctx_arr[i];
                msg[i] = new_buf(RECORD_SIZE, "msg");
                /* Same position-advancing append as the MTL path — see the note
                 * there (raw memcpy left message_len==0; CI run #7). */
                if (mtllib_buffer_append(msg[i], records[i], RECORD_SIZE) != MTLLIB_OK) {
                    fprintf(stderr, "FATAL: mtllib_buffer_append msg[%d] failed (trial %d)\n", i, t);
                    return 1;
                }
                require_ptr("ctx_arr[i] (nonmtl append)", (const void *)c);
                require_buf_data("msg[i] (nonmtl append)", msg[i]);

                struct timespec st; ts_start(&st);
                if (mtllib_sign_append(c, msg[i], &handles[i]) != MTLLIB_OK) {
                    fprintf(stderr, "FATAL: mtllib_sign_append failed rec %d trial %d\n", i, t);
                    return 1;
                }
                require_ptr("handles[i] (get_full_sig)", (const void *)handles[i]);
                size_t cap = mtllib_sign_get_full_sig_length(c, handles[i]);   /* mtllib.h:273 */
                fs[i] = new_buf(cap, "full_sig");
                if (mtllib_sign_get_full_sig(c, handles[i], fs[i]) != MTLLIB_OK) {
                    fprintf(stderr, "FATAL: mtllib_sign_get_full_sig failed rec %d trial %d\n", i, t);
                    return 1;
                }
                sign_time[i] = elapsed_ns(&st);   /* append + full sig (incl. 1-leaf OQS sign) */

                bytes_full[i] = (uint64_t)mtllib_buffer_in_use(fs[i]);
            }

            /* ---------- COLD verify per record: full sig, no pre-verified ladder.
             * The out-param condensed_len gives the condensed portion size used for
             * the warm split below (bytes_condensed for a 1-leaf tree). */
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                require_buf_data("msg[i] (nonmtl cold verify)", msg[i]);
                require_buf_data("fs[i] (nonmtl cold verify)", fs[i]);
                size_t condensed_len = 0;
                struct timespec vt; ts_start(&vt);
                MTLLIB_STATUS r = mtllib_verify(ctx_arr[i], msg[i], fs[i], NULL, &condensed_len);
                v_cold[i] = elapsed_ns(&vt);
                if (!verify_ok(r)) {
                    fprintf(stderr, "FATAL: cold verify FAILED rec %d trial %d (status %d)\n",
                            i, t, (int)r);
                    return 1;
                }
                if ((size_t)condensed_len == 0 || (size_t)condensed_len >= bytes_full[i]) {
                    fprintf(stderr, "FATAL: cold verify condensed_len %zu invalid vs full %" PRIu64
                            " rec %d trial %d\n", condensed_len, bytes_full[i], i, t);
                    return 1;
                }
                cond_len[i] = (uint64_t)condensed_len;
                bytes_cond[i] = cond_len[i];
                if (bytes_cond[i] < cond_min) cond_min = bytes_cond[i];
                if (bytes_cond[i] > cond_max) cond_max = bytes_cond[i];
                cond_sum += bytes_cond[i];
                bytes_ladder_rec[i] = bytes_full[i] - bytes_cond[i];   /* 1-leaf ladder */
            }
            /* nonmtl ladder size is identical across records; use record 0's */
            bytes_signed_ladder = bytes_ladder_rec[0];

            /* ---------- WARM verify: per record, pre-verify that record's own
             * 1-leaf ladder ONCE (accumulated into the BATCH column), then condensed
             * verify against it (parse + auth path, no OQS). The ladder bytes are an
             * EXTERNAL buffer referencing fs[i]'s data after the condensed prefix
             * (external buffers reference caller memory, mtllib_buffer.c:48). */
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                MTLLIB_BUFFER *lad = NULL;
                if (mtllib_buffer_initialize(&lad, (size_t)bytes_ladder_rec[i],
                                             mtllib_buffer_data_ptr(fs[i]) + cond_len[i])
                    != MTLLIB_OK || lad == NULL) {
                    fprintf(stderr, "FATAL: external ladder buffer init failed rec %d trial %d\n", i, t);
                    return 1;
                }
                require_buf_data("lad (nonmtl verify_signed_ladder)", lad);
                struct timespec vt; ts_start(&vt);
                MTLLIB_STATUS r = mtllib_verify_signed_ladder(ctx_arr[i], lad);
                ladder_verify_time_wrm += elapsed_ns(&vt);
                if (r != MTLLIB_OK) {
                    fprintf(stderr, "FATAL: mtllib_verify_signed_ladder FAILED rec %d trial %d (status %d)\n",
                            i, t, (int)r);
                    return 1;
                }

                /* condensed portion: EXTERNAL buffer referencing the first cond_len
                 * bytes of fs[i] — no copy needed for the timed call */
                MTLLIB_BUFFER *cond_view = NULL;
                if (mtllib_buffer_initialize(&cond_view, (size_t)cond_len[i],
                                             mtllib_buffer_data_ptr(fs[i])) != MTLLIB_OK
                    || cond_view == NULL) {
                    fprintf(stderr, "FATAL: external condensed buffer init failed rec %d trial %d\n", i, t);
                    return 1;
                }
                require_buf_data("msg[i] (nonmtl warm verify)", msg[i]);
                require_buf_data("cond_view (nonmtl warm verify)", cond_view);
                require_buf_data("lad (nonmtl warm verify)", lad);
                size_t out_len = 0;
                struct timespec vt2; ts_start(&vt2);
                r = mtllib_verify(ctx_arr[i], msg[i], cond_view, lad, &out_len);
                v_warm[i] = elapsed_ns(&vt2);
                if (!verify_ok(r)) {
                    fprintf(stderr, "FATAL: warm verify FAILED rec %d trial %d (status %d)\n",
                            i, t, (int)r);
                    return 1;
                }
                if ((uint64_t)out_len != cond_len[i]) {
                    fprintf(stderr, "FATAL: warm verify condensed_len mismatch rec %d trial %d\n", i, t);
                    return 1;
                }
                mtllib_buffer_free(cond_view);   /* external: frees struct only */
                mtllib_buffer_free(lad);         /* external: frees struct only */
            }

            /* ---------- cleanup trial (nonmtl) ---------- */
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                mtllib_sign_free_handle(&handles[i]);
                free_buf(msg[i]);
                free_buf(fs[i]);
                mtllib_key_free(ctx_arr[i]);
            }
            free(handles); free(msg); free(fs); free(cond_len); free(ctx_arr);
        }

        /* ---------- CSV rows (recorded trials only; warm-ups are NOT written) ---------- */
        if (!is_warmup) {
            const char *mode_s = (mode == 1) ? "mtl" : "nonmtl";
            uint64_t cond_mean = (N > 0) ? (cond_sum / (uint64_t)N) : 0;
            for (int i = 0; i < N; i++) { g_record = i; /* diagnostics context */
                fprintf(csv,
                    "%d,%s,%d,%" PRIu64 ",%d,%s,%" PRIu64 ","
                    "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                    "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                    "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                    "%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                    t, mode_s, i, seed, N, cfg.algorithm, keygen_time,
                    sign_time[i], ladder_sign_time, v_cold[i],
                    ladder_verify_time_wrm, v_warm[i], bytes_full[i],
                    bytes_cond[i], cond_min, cond_mean,
                    cond_max, bytes_signed_ladder, pubkey_size);
                total_rows++;
            }
        }

        free(sign_time); free(v_cold); free(v_warm);
        free(bytes_full); free(bytes_cond); free(bytes_ladder_rec);
    }

    fclose(csv);
    write_metadata(meta_path, &cfg, cpu_model, kernel, compiler,
                   len_public_key, len_secret_key, len_signature);

    fprintf(stderr, "OK: wrote %d rows to %s ; metadata to %s\n",
            total_rows, cfg.output, meta_path);
    free(records);
    return 0;
}
