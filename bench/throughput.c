#define _POSIX_C_SOURCE 200809L
#include "sarif-writer/sarif-writer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static size_t live, peak;

static void *count_alloc(void *ctx, size_t size)
{
    size_t *block = malloc(size + sizeof(size_t));

    (void)ctx;
    if (block == NULL)
        return NULL;
    *block = size;
    if ((live += size) > peak)
        peak = live;
    return block + 1;
}

static void count_free(void *ctx, void *ptr)
{
    size_t *block = (size_t *)ptr - 1;

    (void)ctx;
    live -= *block;
    free(block);
}

static int count_bytes(void *ctx, const char *data, size_t len)
{
    (void)data;
    *(unsigned long long *)ctx += len;
    return 0;
}

static double seconds(void)
{
    struct timespec t;

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static int write_results(sarw_writer_t *w, long n)
{
    static const sarw_rule_t rule = {"R1", NULL, "rule", NULL, NULL, SARW_LEVEL_ERROR, NULL, 0, NULL, 0, NULL};
    static const sarw_tool_t tool = {"bench", "1", NULL, &rule, 1};
    sarw_prop_t fp = {"bench/v1", "0123456789abcdef0123456789abcdef"}, prop = {"confidence", "high"};
    sarw_location_t loc;
    sarw_result_t r;
    int status = sarw_run_begin(w, &tool);
    long i;

    memset(&loc, 0, sizeof(loc));
    memset(&r, 0, sizeof(r));
    loc.path = "squashfs@0x0/etc/init.d/S50telnet";
    loc.start_line = 3;
    loc.logical_name = "trx@0x0 > squashfs@0x0 > /etc/init.d/S50telnet";
    r.rule_id = "R1";
    r.level = SARW_LEVEL_ERROR;
    r.message = "telnetd started at boot. Evidence: telnetd -l /bin/login";
    r.locations = &loc;
    r.location_count = 1;
    r.fingerprints = &fp;
    r.fingerprint_count = 1;
    r.props = &prop;
    r.prop_count = 1;
    for (i = 0; i < n && status == SARW_OK; i++) {
        r.rule_index = 0;
        status = sarw_result(w, &r);
    }
    if (status == SARW_OK)
        status = sarw_run_end(w, NULL);
    return status == SARW_OK ? sarw_finish(w) : status;
}

int main(int argc, char **argv)
{
    long n = argc > 1 ? atol(argv[1]) : 1000000;
    unsigned long long bytes = 0;
    sarw_writer_t *w = NULL;
    double start, took;
    int status;

    if (sarw_create(count_bytes, &bytes, count_alloc, count_free, NULL, &w) != SARW_OK)
        return 1;
    start = seconds();
    status = write_results(w, n);
    took = seconds() - start;
    sarw_destroy(w);
    printf("results %ld\nbytes %llu\ncpu %.3f s\nresults per second %.0f\npeak memory %zu bytes\n", n, bytes, took,
           took > 0 ? (double)n / took : 0.0, peak);
    return status == SARW_OK ? 0 : 1;
}
