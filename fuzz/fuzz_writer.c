#include "../tests/json_check.h"
#include "sarif-writer/sarif-writer.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} out_t;

static int collect(void *ctx, const char *data, size_t len)
{
    out_t *o = ctx;
    char *grown;

    if (o->len + len > o->cap) {
        if ((grown = realloc(o->data, 2 * (o->len + len))) == NULL)
            return 1;
        o->data = grown;
        o->cap = 2 * (o->len + len);
    }
    memcpy(o->data + o->len, data, len);
    o->len += len;
    return 0;
}

static void call(sarw_writer_t *w, unsigned op, const char *s, int *finished)
{
    sarw_rule_t rule = {s, s, s, NULL, s, (int)(op % 5), NULL, 0, NULL, 0, s};
    sarw_tool_t tool = {s, s, s, &rule, 1};
    sarw_location_t loc;
    sarw_result_t r;

    memset(&loc, 0, sizeof(loc));
    memset(&r, 0, sizeof(r));
    loc.path = (op & 8) ? s : NULL;
    loc.uri = (op & 8) ? NULL : s;
    loc.uri_base_id = (op & 16) ? "B" : NULL;
    loc.start_line = op;
    loc.logical_name = s;
    r.rule_id = s;
    r.rule_index = (int64_t)(op & 1) - 1;
    r.level = (int)(op % 5);
    r.message = s;
    r.locations = &loc;
    r.location_count = 1;
    switch ((op >> 5) & 3) {
    case 0:
        sarw_run_begin(w, &tool);
        break;
    case 1:
        sarw_result(w, &r);
        break;
    case 2:
        sarw_run_end(w, NULL);
        break;
    default:
        *finished = sarw_finish(w) == SARW_OK;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *copy = malloc(size + 1);
    out_t out = {NULL, 0, 0};
    sarw_writer_t *w = NULL;
    size_t at = 0, end;
    int finished = 0;

    if (copy == NULL || sarw_create(collect, &out, NULL, NULL, NULL, &w) != SARW_OK) {
        free(copy);
        return 0;
    }
    memcpy(copy, data, size);
    copy[size] = '\0';
    while (at < size) {
        end = at + strlen(copy + at);
        call(w, (unsigned char)copy[at], copy + at + (end > at), &finished);
        at = end + 1;
    }
    if (finished && !json_valid(out.data, out.len))
        abort();
    sarw_destroy(w);
    free(out.data);
    free(copy);
    return 0;
}
