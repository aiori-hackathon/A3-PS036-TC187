/*
 * Shared helpers for the LadderLens harness programs (bench.c, cachesim.c).
 *
 * Header-only: each program is a single translation unit.
 */
#ifndef LADDERLENS_COMMON_H
#define LADDERLENS_COMMON_H

#include <mtllib.h>
#include <mtllib_util.h>
#include <oqs/oqs.h>
#include <openssl/crypto.h>

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>

#ifndef HARNESS_COMMIT
#define HARNESS_COMMIT unknown
#endif
#ifndef HARNESS_CFLAGS
#define HARNESS_CFLAGS unknown
#endif
#define LL_STR_(x) #x
#define LL_STR(x) LL_STR_(x)

#define LL_DEFAULT_ALG    "SLH-DSA-SHA2-128s-MTL-SHA2-128"
#define LL_LCG_RECORD_LEN 64
#define LL_MAX_RECORDS    100000
#define LL_RECORDS_MAGIC  "LLRECS01"

/* ------------------------------------------------------------------ */
/* Errors                                                             */
/* ------------------------------------------------------------------ */

static inline void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("fatal: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static inline void *xcalloc(size_t n, size_t size)
{
    void *p = calloc(n ? n : 1, size ? size : 1);
    if (!p) die("out of memory");
    return p;
}

/* mtllib_verify returns MTLLIB_OK with a caller-supplied ladder and
 * MTLLIB_OK_VALIDATED_LADDER when it validated the ladder carried in a full
 * signature (mtl-ref/src/mtllib.c, mtllib_verify_with_ctx_str). */
static inline int verify_ok(MTLLIB_STATUS s)
{
    return s == MTLLIB_OK || s == MTLLIB_OK_VALIDATED_LADDER;
}

/* ------------------------------------------------------------------ */
/* Timing (CLOCK_MONOTONIC)                                           */
/* ------------------------------------------------------------------ */

static inline uint64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) die("clock_gettime failed");
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static inline int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Median cost of one back-to-back timer read: the noise floor below which
 * no per-operation timing in this harness is meaningful. */
static inline uint64_t timer_overhead_ns(void)
{
    enum { SAMPLES = 10001 };
    static uint64_t d[SAMPLES];
    for (int i = 0; i < SAMPLES; i++) {
        uint64_t a = now_ns();
        uint64_t b = now_ns();
        d[i] = b - a;
    }
    qsort(d, SAMPLES, sizeof(d[0]), cmp_u64);
    return d[SAMPLES / 2];
}

static inline uint64_t timer_resolution_ns(void)
{
    struct timespec r;
    if (clock_getres(CLOCK_MONOTONIC, &r) != 0) return 0;
    return (uint64_t)r.tv_sec * 1000000000ULL + (uint64_t)r.tv_nsec;
}

/* ------------------------------------------------------------------ */
/* MTLLIB_BUFFER helpers                                              */
/* ------------------------------------------------------------------ */

/* Empty buffer that owns `capacity` bytes of storage. */
static inline MTLLIB_BUFFER *buf_new(size_t capacity)
{
    MTLLIB_BUFFER *b = NULL;
    if (mtllib_buffer_initialize(&b, capacity ? capacity : 1, NULL) != MTLLIB_OK || !b)
        die("mtllib_buffer_initialize failed");
    return b;
}

/* Owned copy of `len` bytes. mtllib_buffer_append advances the write position,
 * which is what in_use() reports to the library. */
static inline MTLLIB_BUFFER *buf_copy(const uint8_t *data, size_t len)
{
    MTLLIB_BUFFER *b = buf_new(len);
    if (mtllib_buffer_append(b, (uint8_t *)data, len) != MTLLIB_OK) die("mtllib_buffer_append failed");
    return b;
}

/* Non-owning view of caller memory (freed with mtllib_buffer_free, data untouched). */
static inline MTLLIB_BUFFER *buf_view(const uint8_t *data, size_t len)
{
    MTLLIB_BUFFER *b = NULL;
    if (mtllib_buffer_initialize(&b, len, (uint8_t *)data) != MTLLIB_OK || !b)
        die("mtllib_buffer_initialize (view) failed");
    return b;
}

static inline MTLLIB_BUFFER *buf_concat(MTLLIB_BUFFER *a, MTLLIB_BUFFER *b)
{
    size_t la = mtllib_buffer_in_use(a), lb = mtllib_buffer_in_use(b);
    MTLLIB_BUFFER *out = buf_new(la + lb);
    if (mtllib_buffer_append(out, mtllib_buffer_data_ptr(a), la) != MTLLIB_OK ||
        mtllib_buffer_append(out, mtllib_buffer_data_ptr(b), lb) != MTLLIB_OK)
        die("buffer concatenation failed");
    return out;
}

/* Public-key-only verifier context, as a resolver would hold it. The series
 * identifier is read from the signature at offset 2, after the 2-byte flags
 * field (same as mtl-ref/examples/mtlverify.c). */
static inline MTLLIB_CTX *verifier_from(MTLLIB_CTX *signer, char *alg, MTLLIB_BUFFER *any_sig)
{
    size_t len = mtllib_pubkey_to_buffer_length(signer);
    MTLLIB_BUFFER *pk = buf_new(len);
    if (mtllib_pubkey_to_buffer(signer, pk) != MTLLIB_OK) die("mtllib_pubkey_to_buffer failed");
    MTLLIB_CTX *v = NULL;
    if (mtllib_pubkey_from_buffer(alg, &v, pk, mtllib_buffer_data_ptr(any_sig) + 2) != MTLLIB_OK || !v)
        die("mtllib_pubkey_from_buffer failed");
    mtllib_buffer_free(pk);
    return v;
}

static inline size_t pubkey_bytes(MTLLIB_CTX *ctx)
{
    MTLLIB_BUFFER *pk = buf_new(mtllib_pubkey_to_buffer_length(ctx));
    if (mtllib_pubkey_to_buffer(ctx, pk) != MTLLIB_OK) die("mtllib_pubkey_to_buffer failed");
    size_t n = mtllib_buffer_in_use(pk);
    mtllib_buffer_free(pk);
    return n;
}

/* ------------------------------------------------------------------ */
/* Records                                                            */
/*                                                                    */
/* A records file holds the exact bytes that DNSSEC signs for each     */
/* RRset (RRSIG RDATA without the signature, followed by the RRset in  */
/* canonical form; RFC 4034 section 3.1.8.1). It is produced by        */
/* `python3 -m ladderlens fixtures`. Layout:                           */
/*   "LLRECS01" | uint32 count | count x (uint32 length | bytes)       */
/* All integers are big-endian.                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    size_t    count;
    uint8_t **data;
    size_t   *len;
    char      source[512];
} records_t;

static inline uint32_t read_be32(FILE *f, const char *path)
{
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4) die("%s: truncated", path);
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

static inline void records_load(const char *path, size_t need, records_t *r)
{
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open records file %s: %s", path, strerror(errno));
    char magic[8];
    if (fread(magic, 1, 8, f) != 8 || memcmp(magic, LL_RECORDS_MAGIC, 8) != 0)
        die("%s: not a LadderLens records file", path);
    size_t count = read_be32(f, path);
    if (count < need) die("%s holds %zu records, %zu needed", path, count, need);
    r->count = need;
    r->data = xcalloc(need, sizeof(uint8_t *));
    r->len = xcalloc(need, sizeof(size_t));
    for (size_t i = 0; i < need; i++) {
        uint32_t n = read_be32(f, path);
        if (n == 0 || n > 65535) die("%s: record %zu has invalid length %u", path, i, n);
        r->data[i] = xcalloc(n, 1);
        if (fread(r->data[i], 1, n, f) != n) die("%s: truncated at record %zu", path, i);
        r->len[i] = n;
    }
    fclose(f);
    snprintf(r->source, sizeof(r->source), "%s", path);
}

/* Fallback when no fixture is given: fixed-length pseudo-random records from a
 * non-cryptographic LCG. Record content only affects leaf hashing. */
static inline void records_lcg(uint64_t seed, size_t n, records_t *r)
{
    uint64_t x = seed ? seed : 0x9E3779B97F4A7C15ULL;
    r->count = n;
    r->data = xcalloc(n, sizeof(uint8_t *));
    r->len = xcalloc(n, sizeof(size_t));
    for (size_t i = 0; i < n; i++) {
        r->data[i] = xcalloc(LL_LCG_RECORD_LEN, 1);
        r->len[i] = LL_LCG_RECORD_LEN;
        for (int j = 0; j < LL_LCG_RECORD_LEN; j++) {
            x = x * 6364136223846793005ULL + 1442695040888963407ULL;
            r->data[i][j] = (uint8_t)(x >> 33);
        }
    }
    snprintf(r->source, sizeof(r->source), "lcg-%d-bytes", LL_LCG_RECORD_LEN);
}

static inline void records_free(records_t *r)
{
    for (size_t i = 0; i < r->count; i++) free(r->data[i]);
    free(r->data);
    free(r->len);
    memset(r, 0, sizeof(*r));
}

/* ------------------------------------------------------------------ */
/* Files and metadata                                                 */
/* ------------------------------------------------------------------ */

static inline void mkdirs_for(const char *file_path)
{
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s", file_path);
    char *slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) die("mkdir %s: %s", tmp, strerror(errno));
        *p = '/';
    }
    if (tmp[0] && mkdir(tmp, 0755) != 0 && errno != EEXIST) die("mkdir %s: %s", tmp, strerror(errno));
}

/* "dir/name.csv" -> "dir/name<suffix>" */
static inline void sibling_path(const char *path, const char *suffix, char *out, size_t outn)
{
    size_t n = strlen(path);
    if (n > 4 && strcmp(path + n - 4, ".csv") == 0)
        snprintf(out, outn, "%.*s%s", (int)(n - 4), path, suffix);
    else
        snprintf(out, outn, "%s%s", path, suffix);
}

static inline void json_string(FILE *f, const char *key, const char *val, int comma)
{
    fprintf(f, "  \"%s\": \"", key);
    for (const char *p = val ? val : ""; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fprintf(f, "\"%s\n", comma ? "," : "");
}

static inline void json_u64(FILE *f, const char *key, uint64_t v, int comma)
{
    fprintf(f, "  \"%s\": %" PRIu64 "%s\n", key, v, comma ? "," : "");
}

static inline void cpu_model(char *out, size_t outn)
{
    snprintf(out, outn, "unknown");
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "model name", 10) != 0) continue;
        char *v = strchr(line, ':');
        if (!v) break;
        v++;
        while (*v == ' ' || *v == '\t') v++;
        v[strcspn(v, "\r\n")] = '\0';
        snprintf(out, outn, "%s", v);
        break;
    }
    fclose(f);
}

/* Environment block shared by both programs' metadata files. */
static inline void json_environment(FILE *f)
{
    char cpu[256];
    struct utsname u;
    cpu_model(cpu, sizeof(cpu));
    json_string(f, "cpu_model", cpu, 1);
    json_string(f, "kernel", uname(&u) == 0 ? u.release : "unknown", 1);
    json_string(f, "compiler", "gcc " __VERSION__, 1);
    json_string(f, "harness_commit", LL_STR(HARNESS_COMMIT), 1);
    json_string(f, "harness_cflags", LL_STR(HARNESS_CFLAGS), 1);
    json_string(f, "openssl_version", OpenSSL_version(OPENSSL_VERSION), 1);
    json_string(f, "liboqs_version", OQS_version(), 1);
    json_string(f, "mtl_lib_version", MTL_LIB_VERSION, 1);
    json_string(f, "mtl_ref_commit", getenv("MTL_REF_COMMIT"), 1);
    json_string(f, "mtl_cflags", getenv("MTL_CFLAGS"), 1);
    json_string(f, "openssl_sha", getenv("OPENSSL_SHA"), 1);
    json_string(f, "liboqs_sha", getenv("LIBOQS_SHA"), 1);
    json_string(f, "clock", "CLOCK_MONOTONIC", 1);
    json_u64(f, "timer_resolution_ns", timer_resolution_ns(), 1);
    json_u64(f, "timer_overhead_ns", timer_overhead_ns(), 1);
}

#endif /* LADDERLENS_COMMON_H */
