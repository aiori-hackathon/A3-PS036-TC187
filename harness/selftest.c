/*
 * selftest: cryptographic correctness checks for the configured algorithm.
 *
 * Valid signatures must be accepted. Altered messages, altered signatures,
 * altered or foreign ladders, truncated and malformed signatures, and records a
 * ladder does not cover must be rejected. Every case runs in its own child
 * process, so a crash inside the reference library on malformed input is
 * reported as a crash instead of ending the whole run.
 *
 * Output: one line per case, "ok   <name>" or "FAIL <name>: <reason>", then a
 * summary. Exit status 0 only if every case behaves as expected.
 */
#include "common.h"

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#define N_RECORDS 8   /* non-power-of-two batches are covered by make verify; 8 gives a full auth path */

static char alg[256] = LL_DEFAULT_ALG;
static const char *oqs_alg;
static records_t recs;

/* MTL state shared (copy-on-write) with every child */
static MTLLIB_CTX *signer, *verifier, *other_signer;
static MTLLIB_BUFFER *msg[N_RECORDS], *cond[N_RECORDS], *full[N_RECORDS], *ladder, *other_ladder;

/* Copy of `b` with byte `pos` flipped (pos < 0 counts from the end). */
static MTLLIB_BUFFER *flipped(MTLLIB_BUFFER *b, long pos)
{
    size_t n = mtllib_buffer_in_use(b);
    MTLLIB_BUFFER *c = buf_copy(mtllib_buffer_data_ptr(b), n);
    size_t at = pos < 0 ? n - (size_t)(-pos) : (size_t)pos;
    mtllib_buffer_data_ptr(c)[at] ^= 0x01;
    return c;
}

static MTLLIB_BUFFER *truncated(MTLLIB_BUFFER *b, size_t keep)
{
    return buf_copy(mtllib_buffer_data_ptr(b), keep);
}

static int accepted(MTLLIB_STATUS s) { return verify_ok(s); }

static int check_sig(MTLLIB_BUFFER *m, MTLLIB_BUFFER *sig, MTLLIB_BUFFER *lad)
{
    size_t clen = 0;
    return accepted(mtllib_verify(verifier, m, sig, lad, &clen));
}

/* ---- cases: return 1 when the outcome is the expected one ---- */

static int plain_case(int which)
{
    OQS_SIG *s = OQS_SIG_new(oqs_alg);
    if (!s) return 0;
    uint8_t *pk = xcalloc(s->length_public_key, 1), *sk = xcalloc(s->length_secret_key, 1);
    uint8_t *sig = xcalloc(s->length_signature, 1);
    uint8_t *m = xcalloc(recs.len[0], 1);
    memcpy(m, recs.data[0], recs.len[0]);
    size_t slen = 0;
    if (OQS_SIG_keypair(s, pk, sk) != OQS_SUCCESS || OQS_SIG_sign(s, sig, &slen, m, recs.len[0], sk) != OQS_SUCCESS)
        return 0;
    switch (which) {
    case 0: return OQS_SIG_verify(s, m, recs.len[0], sig, slen, pk) == OQS_SUCCESS;
    case 1: m[0] ^= 1;   return OQS_SIG_verify(s, m, recs.len[0], sig, slen, pk) != OQS_SUCCESS;
    case 2: sig[slen / 2] ^= 1; return OQS_SIG_verify(s, m, recs.len[0], sig, slen, pk) != OQS_SUCCESS;
    case 3: return OQS_SIG_verify(s, m, recs.len[0], sig, slen - 1, pk) != OQS_SUCCESS;
    }
    return 0;
}

static int c_plain_valid(void)      { return plain_case(0); }
static int c_plain_msg(void)        { return plain_case(1); }
static int c_plain_sig(void)        { return plain_case(2); }
static int c_plain_trunc(void)      { return plain_case(3); }

static int c_full_valid(void)       { return check_sig(msg[3], full[3], NULL); }
static int c_warm_valid(void)
{
    return mtllib_verify_signed_ladder(verifier, ladder) == MTLLIB_OK && check_sig(msg[3], cond[3], ladder);
}
static int c_full_msg(void)         { return !check_sig(msg[4], full[3], NULL); }
static int c_warm_msg(void)         { return !check_sig(msg[4], cond[3], ladder); }
static int c_cond_path_end(void)    { return !check_sig(msg[3], flipped(cond[3], -1), ladder); }
static int c_cond_path_mid(void)
{
    return !check_sig(msg[3], flipped(cond[3], (long)mtllib_buffer_in_use(cond[3]) - 20), ladder);
}
static int c_ladder_sig(void)       { return mtllib_verify_signed_ladder(verifier, flipped(ladder, -1)) != MTLLIB_OK; }
static int c_full_bad_ladder(void)  { return !check_sig(msg[3], buf_concat(cond[3], flipped(ladder, -1)), NULL); }
static int c_foreign_ladder(void)   { return mtllib_verify_signed_ladder(verifier, other_ladder) != MTLLIB_OK; }
static int c_cond_foreign(void)     { return !check_sig(msg[3], cond[3], other_ladder); }
static int c_trunc_cond(void)       { return !check_sig(msg[3], truncated(cond[3], 10), ladder); }
static int c_trunc_full(void)       { return !check_sig(msg[3], truncated(full[3], mtllib_buffer_in_use(full[3]) - 100), NULL); }
static int c_empty_sig(void)        { return !check_sig(msg[3], truncated(cond[3], 0), ladder); }
static int c_garbage(void)
{
    MTLLIB_BUFFER *g = buf_new(256);
    uint8_t junk[256];
    for (int i = 0; i < 256; i++) junk[i] = (uint8_t)(i * 37 + 11);
    mtllib_buffer_append(g, junk, sizeof(junk));
    return !check_sig(msg[3], g, ladder) && !check_sig(msg[3], g, NULL);
}

static int c_uncovered(void)
{
    /* Grow the tree after the ladder was signed: the new record's signature
     * cannot be checked against the older ladder. */
    MTLLIB_BUFFER *extra = buf_copy(recs.data[N_RECORDS], recs.len[N_RECORDS]);
    MTL_HANDLE *h = NULL;
    if (mtllib_sign_append(signer, extra, &h) != MTLLIB_OK) return 0;
    MTLLIB_BUFFER *c = buf_new(mtllib_sign_get_condensed_sig_length(signer, h));
    if (mtllib_sign_get_condensed_sig(signer, h, c) != MTLLIB_OK) return 0;
    return !check_sig(extra, c, ladder);
}

typedef struct { const char *name; int (*fn)(void); } test_case;

static const test_case CASES[] = {
    { "plain: valid signature accepted",                       c_plain_valid },
    { "plain: altered message rejected",                       c_plain_msg },
    { "plain: altered signature rejected",                     c_plain_sig },
    { "plain: truncated signature rejected",                   c_plain_trunc },
    { "mtl: full signature accepted (cold)",                   c_full_valid },
    { "mtl: condensed signature accepted on verified ladder",  c_warm_valid },
    { "mtl: full signature on another record rejected",        c_full_msg },
    { "mtl: condensed signature on another record rejected",   c_warm_msg },
    { "mtl: altered authentication path (last byte) rejected", c_cond_path_end },
    { "mtl: altered authentication path (inner byte) rejected", c_cond_path_mid },
    { "mtl: altered ladder signature rejected",                c_ladder_sig },
    { "mtl: full signature with altered ladder rejected",      c_full_bad_ladder },
    { "mtl: ladder signed by another key rejected",            c_foreign_ladder },
    { "mtl: condensed signature against another key's ladder rejected", c_cond_foreign },
    { "mtl: truncated condensed signature rejected",           c_trunc_cond },
    { "mtl: truncated full signature rejected",                c_trunc_full },
    { "mtl: empty signature rejected",                         c_empty_sig },
    { "mtl: malformed signature rejected",                     c_garbage },
    { "mtl: record not covered by the ladder rejected",        c_uncovered },
};

static void setup(void)
{
    MTL_ALGORITHM_PROPS *props = mtllib_util_get_algorithm_props(alg);
    if (!props || props->library != LIBOQS) die("unsupported algorithm %s", alg);
    oqs_alg = props->scheme_str;
    records_lcg(36, N_RECORDS + 1, &recs);

    if (mtllib_key_new(alg, &signer) != MTLLIB_OK) die("mtllib_key_new failed");
    MTL_HANDLE *h[N_RECORDS];
    for (int i = 0; i < N_RECORDS; i++) {
        msg[i] = buf_copy(recs.data[i], recs.len[i]);
        if (mtllib_sign_append(signer, msg[i], &h[i]) != MTLLIB_OK) die("append failed");
    }
    ladder = buf_new(mtllib_sign_get_signed_ladder_length(signer));
    if (mtllib_sign_get_signed_ladder(signer, ladder) != MTLLIB_OK) die("ladder signing failed");
    for (int i = 0; i < N_RECORDS; i++) {
        cond[i] = buf_new(mtllib_sign_get_condensed_sig_length(signer, h[i]));
        if (mtllib_sign_get_condensed_sig(signer, h[i], cond[i]) != MTLLIB_OK) die("condensed signature failed");
        full[i] = buf_concat(cond[i], ladder);
    }
    verifier = verifier_from(signer, alg, cond[0]);

    /* A second, unrelated key over the same records. */
    if (mtllib_key_new(alg, &other_signer) != MTLLIB_OK) die("mtllib_key_new failed");
    for (int i = 0; i < N_RECORDS; i++) {
        MTL_HANDLE *oh = NULL;
        if (mtllib_sign_append(other_signer, msg[i], &oh) != MTLLIB_OK) die("append failed");
    }
    other_ladder = buf_new(mtllib_sign_get_signed_ladder_length(other_signer));
    if (mtllib_sign_get_signed_ladder(other_signer, other_ladder) != MTLLIB_OK) die("ladder signing failed");
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--algorithm")) snprintf(alg, sizeof(alg), "%s", argv[2]);
    else if (argc != 1) { fprintf(stderr, "usage: selftest [--algorithm ALG]\n"); return 2; }
    setup();
    printf("selftest: %s\n", alg);
    fflush(stdout);

    int failures = 0;
    const int n = (int)(sizeof(CASES) / sizeof(CASES[0]));
    for (int i = 0; i < n; i++) {
        pid_t pid = fork();
        if (pid < 0) die("fork failed");
        if (pid == 0) {
            /* The library logs its own rejections; keep this output to our lines. */
            if (!freopen("/dev/null", "w", stderr)) _exit(3);
            _exit(CASES[i].fn() ? 0 : 1);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            printf("ok   %s\n", CASES[i].name);
        } else {
            failures++;
            if (WIFSIGNALED(status))
                printf("FAIL %s: crashed with signal %d (%s)\n", CASES[i].name, WTERMSIG(status), strsignal(WTERMSIG(status)));
            else
                printf("FAIL %s: unexpected result\n", CASES[i].name);
        }
        fflush(stdout);
    }
    printf("selftest: %d of %d cases as expected\n", n - failures, n);
    return failures ? 1 : 0;
}
