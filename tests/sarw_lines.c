#include "sarif-writer/sarif-writer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FIELDS 4096
#define MAX_RULES 1024
#define MAX_LOCS 64
#define MAX_PROPS 64

typedef struct {
    char *f[MAX_FIELDS];
    size_t n;
    size_t at;
} line_t;

static int put(void *ctx, const char *data, size_t len)
{
    (void)ctx;
    return fwrite(data, 1, len, stdout) == len ? 0 : 1;
}

static int unhex(char *s)
{
    size_t i, n = strlen(s);
    unsigned v;

    if (n % 2 != 0)
        return 0;
    for (i = 0; i < n; i += 2) {
        if (sscanf(s + i, "%2x", &v) != 1)
            return 0;
        s[i / 2] = (char)v;
    }
    s[n / 2] = '\0';
    return 1;
}

static int split(char *text, line_t *l)
{
    char *tok = strtok(text, " \n");

    l->n = l->at = 0;
    while (tok != NULL && l->n < MAX_FIELDS) {
        if (l->n > 0 && strcmp(tok, "-") == 0)
            l->f[l->n++] = NULL;
        else if (l->n > 0 && strcmp(tok, "=") == 0)
            l->f[l->n++] = tok + 1;
        else if (l->n == 0 || unhex(tok))
            l->f[l->n++] = tok;
        else
            return 0;
        tok = strtok(NULL, " \n");
    }
    return tok == NULL && l->n > 0;
}

static const char *str(line_t *l)
{
    if (l->at >= l->n) {
        fprintf(stderr, "sarw_lines: line too short\n");
        exit(1);
    }
    return l->f[l->at++];
}

static unsigned long long num(line_t *l)
{
    const char *s = str(l);

    return s != NULL ? strtoull(s, NULL, 10) : 0;
}

static size_t count(line_t *l, size_t max)
{
    size_t n = (size_t)num(l);

    if (n > max) {
        fprintf(stderr, "sarw_lines: count over %zu\n", max);
        exit(1);
    }
    return n;
}

static size_t props(line_t *l, sarw_prop_t *out)
{
    size_t n = count(l, MAX_PROPS), i;

    for (i = 0; i < n; i++) {
        out[i].key = str(l);
        out[i].value = str(l);
    }
    return n;
}

static size_t locations(line_t *l, sarw_location_t *out)
{
    size_t n = count(l, MAX_LOCS), i;

    for (i = 0; i < n; i++) {
        out[i].path = str(l);
        out[i].uri = str(l);
        out[i].uri_base_id = str(l);
        out[i].start_line = num(l);
        out[i].start_column = num(l);
        out[i].end_line = num(l);
        out[i].end_column = num(l);
        out[i].has_byte_offset = (int)num(l);
        out[i].byte_offset = num(l);
        out[i].byte_length = num(l);
        out[i].logical_name = str(l);
        out[i].message = str(l);
    }
    return n;
}

typedef struct {
    sarw_tool_t tool;
    sarw_rule_t rules[MAX_RULES];
    const char *tags[MAX_RULES][MAX_PROPS];
    sarw_prop_t rule_props[MAX_RULES][MAX_PROPS];
    sarw_location_t loc[MAX_LOCS], rel[MAX_LOCS];
    sarw_prop_t fp[MAX_PROPS], rp[MAX_PROPS];
    sarw_notification_t notes[MAX_PROPS];
    sarw_invocation_t inv;
    sarw_run_tail_t tail;
} state_t;

static int run_end(line_t *l, state_t *st, sarw_writer_t *w)
{
    size_t i;

    memset(&st->tail, 0, sizeof(st->tail));
    st->tail.artifact_count = locations(l, st->loc);
    st->tail.artifacts = st->loc;
    if (num(l) != 0) {
        st->inv.command_line = str(l);
        st->inv.execution_successful = (int)num(l);
        st->inv.notification_count = count(l, MAX_PROPS);
        for (i = 0; i < st->inv.notification_count; i++) {
            st->notes[i].level = (int)num(l);
            st->notes[i].message = str(l);
        }
        st->inv.notifications = st->notes;
        st->tail.invocation = &st->inv;
    }
    return sarw_run_end(w, &st->tail);
}

static void rule(line_t *l, state_t *st)
{
    sarw_rule_t *r = &st->rules[st->tool.rule_count];
    size_t i;

    r->id = str(l);
    r->name = str(l);
    r->short_description = str(l);
    r->full_description = str(l);
    r->help_text = str(l);
    r->level = (int)num(l);
    r->tag_count = count(l, MAX_PROPS);
    for (i = 0; i < r->tag_count; i++)
        st->tags[st->tool.rule_count][i] = str(l);
    r->tags = st->tags[st->tool.rule_count];
    r->prop_count = props(l, st->rule_props[st->tool.rule_count]);
    r->props = st->rule_props[st->tool.rule_count];
    r->help_uri = str(l);
    st->tool.rule_count++;
}

static int result(line_t *l, state_t *st, sarw_writer_t *w)
{
    sarw_result_t r;
    const char *index;

    memset(&r, 0, sizeof(r));
    r.rule_id = str(l);
    index = str(l);
    r.rule_index = index != NULL ? (int64_t)strtoll(index, NULL, 10) : -1;
    r.level = (int)num(l);
    r.message = str(l);
    r.location_count = locations(l, st->loc);
    r.locations = st->loc;
    r.related_count = locations(l, st->rel);
    r.related = st->rel;
    r.fingerprint_count = props(l, st->fp);
    r.fingerprints = st->fp;
    r.prop_count = props(l, st->rp);
    r.props = st->rp;
    return sarw_result(w, &r);
}

static int record(line_t *l, state_t *st, sarw_writer_t *w)
{
    char kind = l->f[l->at++][0];

    if (kind != 'R' && st->tool.name != NULL) {
        int status = sarw_run_begin(w, &st->tool);

        memset(&st->tool, 0, sizeof(st->tool));
        st->tool.rules = st->rules;
        if (status != SARW_OK)
            return status;
    }
    switch (kind) {
    case 'T':
        st->tool.name = str(l);
        st->tool.version = str(l);
        st->tool.information_uri = str(l);
        return SARW_OK;
    case 'R':
        rule(l, st);
        return SARW_OK;
    case 'S':
        return result(l, st, w);
    case 'E':
        return run_end(l, st, w);
    default:
        return sarw_finish(w);
    }
}

static char *read_all(void)
{
    size_t len = 0, cap = 1 << 16, got;
    char *buf = malloc(cap + 1), *grown;

    while (buf != NULL && (got = fread(buf + len, 1, cap - len, stdin)) > 0) {
        len += got;
        if (len == cap && (grown = realloc(buf, 2 * cap + 1)) != NULL) {
            buf = grown;
            cap *= 2;
        } else if (len == cap) {
            free(buf);
            return NULL;
        }
    }
    if (buf != NULL)
        buf[len] = '\0';
    return buf;
}

int main(void)
{
    static line_t line;
    static state_t st;
    sarw_writer_t *w = NULL;
    char *all = read_all(), *at, *next;
    size_t number = 0;
    int status = SARW_OK;

    st.tool.rules = st.rules;
    if (all == NULL || sarw_create(put, NULL, NULL, NULL, NULL, &w) != SARW_OK)
        return 1;
    for (at = all; status == SARW_OK && *at != '\0'; at = next) {
        next = at + strcspn(at, "\n");
        if (*next != '\0')
            *next++ = '\0';
        number++;
        if (!split(at, &line))
            status = SARW_ERR_ARG;
        else
            status = record(&line, &st, w);
    }
    if (status != SARW_OK)
        fprintf(stderr, "sarw_lines: line %zu: %s\n", number, sarw_strerror(status));
    sarw_destroy(w);
    free(all);
    return status == SARW_OK ? 0 : 1;
}
