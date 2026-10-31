#include "sarif-writer/sarif-writer.h"
#include "json_check.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                                                     \
    do {                                                                                                \
        if (!(cond)) {                                                                                  \
            fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond);                           \
            exit(1);                                                                                    \
        }                                                                                               \
    } while (0)

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    long fail_at;
    long calls;
} sink_t;

static int sink_write(void *ctx, const char *data, size_t len)
{
    sink_t *s = ctx;

    if (s->fail_at >= 0 && s->calls++ >= s->fail_at)
        return -1;
    if (s->len + len + 1 > s->cap) {
        s->cap = 2 * (s->len + len + 1);
        s->data = realloc(s->data, s->cap);
        CHECK(s->data != NULL);
    }
    memcpy(s->data + s->len, data, len);
    s->len += len;
    s->data[s->len] = '\0';
    return 0;
}

static sarw_writer_t *writer_on(sink_t *s, long fail_at)
{
    sarw_writer_t *w = NULL;

    memset(s, 0, sizeof(*s));
    s->fail_at = fail_at;
    CHECK(sarw_create(sink_write, s, NULL, NULL, NULL, &w) == SARW_OK && w != NULL);
    return w;
}

static const char *const tags[] = {"security"};
static const sarw_prop_t severity[] = {{"security-severity", "8.0"}};
static const sarw_rule_t rule = {"R1", NULL, "s", NULL, NULL, SARW_LEVEL_ERROR, tags, 1, severity, 1, NULL};
static const sarw_tool_t tool = {"t", NULL, NULL, &rule, 1};

static sarw_result_t result_at(const sarw_location_t *loc)
{
    sarw_result_t r;

    memset(&r, 0, sizeof(r));
    r.rule_id = "R1";
    r.rule_index = 0;
    r.level = SARW_LEVEL_ERROR;
    r.message = "m";
    r.locations = loc;
    r.location_count = loc != NULL;
    return r;
}

static const char golden[] =
    "{\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n  \"version\": \"2.1.0\",\n"
    "  \"runs\": [\n    {\n      \"tool\": {\n        \"driver\": {\n          \"name\": \"t\",\n"
    "          \"rules\": [\n            {\n              \"id\": \"R1\",\n"
    "              \"shortDescription\": {\n                \"text\": \"s\"\n              },\n"
    "              \"defaultConfiguration\": {\n                \"level\": \"error\"\n              },\n"
    "              \"properties\": {\n                \"tags\": [\n                  \"security\"\n"
    "                ],\n                \"security-severity\": \"8.0\"\n              }\n            }\n"
    "          ]\n        }\n      },\n      \"results\": [\n        {\n          \"ruleId\": \"R1\",\n"
    "          \"ruleIndex\": 0,\n          \"level\": \"error\",\n          \"message\": {\n"
    "            \"text\": \"m\"\n          },\n          \"locations\": [\n            {\n"
    "              \"physicalLocation\": {\n                \"artifactLocation\": {\n"
    "                  \"uri\": \"etc/a%20b\"\n                },\n                \"region\": {\n"
    "                  \"startLine\": 3\n                }\n              }\n            }\n          ]\n"
    "        }\n      ]\n    }\n  ]\n}\n";

static void test_golden(void)
{
    sink_t s;
    sarw_writer_t *w = writer_on(&s, -1);
    sarw_location_t loc;
    sarw_result_t r;

    memset(&loc, 0, sizeof(loc));
    loc.path = "etc/a b";
    loc.start_line = 3;
    r = result_at(&loc);
    CHECK(sarw_run_begin(w, &tool) == SARW_OK);
    CHECK(sarw_result(w, &r) == SARW_OK);
    CHECK(sarw_run_end(w, NULL) == SARW_OK);
    CHECK(sarw_finish(w) == SARW_OK);
    CHECK(s.len == sizeof(golden) - 1 && memcmp(s.data, golden, s.len) == 0);
    CHECK(json_valid(s.data, s.len) && sarw_warnings(w) == 0);
    sarw_destroy(w);
    free(s.data);
}

static int document(sink_t *s, const sarw_location_t *loc, const char *message, const sarw_run_tail_t *tail)
{
    sarw_writer_t *w = writer_on(s, -1);
    sarw_result_t r = result_at(loc);
    int status;

    r.message = message;
    CHECK(sarw_run_begin(w, &tool) == SARW_OK);
    status = sarw_result(w, &r);
    CHECK(sarw_run_end(w, tail) == SARW_OK);
    CHECK(sarw_finish(w) == SARW_OK);
    CHECK(json_valid(s->data, s->len));
    s->calls = (long)sarw_warnings(w);
    sarw_destroy(w);
    return status;
}

static void test_escape(void)
{
    sink_t s;

    CHECK(document(&s, NULL, "q\"b\\n\nt\t\x01\x1f\x7f/\xc3\xa9 bad\xff\xc3(\xed\xa0\x80", NULL) == SARW_OK);
    CHECK(strstr(s.data, "\"text\": \"q\\\"b\\\\n\\nt\\t\\u0001\\u001f\x7f/\xc3\xa9 bad\xef\xbf\xbd\xef\xbf\xbd("
                         "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\"") != NULL);
    CHECK(s.calls == SARW_WARN_UTF8);
    free(s.data);
}

static void uri_case(const char *path, const char *base, const char *want)
{
    sink_t s;
    sarw_location_t loc;
    char needle[256];

    memset(&loc, 0, sizeof(loc));
    loc.path = path;
    loc.uri_base_id = base;
    if (want == NULL) {
        CHECK(document(&s, &loc, "m", NULL) == SARW_ERR_ARG);
        CHECK(strstr(s.data, "\"uri\"") == NULL);
    } else {
        CHECK(document(&s, &loc, "m", NULL) == SARW_OK);
        snprintf(needle, sizeof(needle), "\"uri\": \"%s\"", want);
        CHECK(strstr(s.data, needle) != NULL);
    }
    free(s.data);
}

static void test_uri(void)
{
    uri_case("etc/passwd", NULL, "etc/passwd");
    uri_case("./a//b/../c/.", "SRCROOT", "a/c");
    uri_case("a b%:#?[]", NULL, "a%20b%25%3A%23%3F%5B%5D");
    uri_case("trx@0x0/part@1/x~y-z_w.(1)", NULL, "trx@0x0/part@1/x~y-z_w.(1)");
    uri_case("\xc3\xa9t\xc3\xa9", NULL, "%C3%A9t%C3%A9");
    uri_case("/usr/bin/x", NULL, "file:///usr/bin/x");
    uri_case("/../x", NULL, "file:///x");
    uri_case("/", NULL, "file:///");
    uri_case("C:\\x\\y z", NULL, "file:///C:/x/y%20z");
    uri_case("C:\\..\\..\\x", NULL, "file:///C:/x");
    uri_case("/abs", "SRCROOT", NULL);
    uri_case("C:\\abs", "SRCROOT", NULL);
    uri_case("../x", NULL, NULL);
    uri_case("a/../..", NULL, NULL);
    uri_case(".", NULL, NULL);
    uri_case("", NULL, NULL);
}

static void test_tail(void)
{
    sink_t s;
    sarw_location_t art[2];
    sarw_notification_t note = {"took \"long\"", SARW_LEVEL_WARNING};
    sarw_invocation_t inv = {"scan a.bin", 1, &note, 1};
    sarw_run_tail_t tail = {art, 2, &inv};

    memset(art, 0, sizeof(art));
    art[0].path = "a.bin";
    art[0].uri_base_id = "ROOT";
    art[1].uri = "https://example.com/x";
    CHECK(document(&s, NULL, "m", &tail) == SARW_OK);
    CHECK(strstr(s.data, "\"artifacts\": [\n        {\n          \"location\": {\n            \"uri\": \"a.bin\",\n"
                         "            \"uriBaseId\": \"ROOT\"\n") != NULL);
    CHECK(strstr(s.data, "\"executionSuccessful\": true,\n          \"toolExecutionNotifications\": [") != NULL);
    CHECK(strstr(s.data, "\"text\": \"took \\\"long\\\"\"") != NULL);
    free(s.data);
    art[1].uri = NULL;
    CHECK(document(&s, NULL, "m", NULL) == SARW_OK);
    free(s.data);
}

static void test_arguments(void)
{
    sink_t s;
    sarw_writer_t *w = writer_on(&s, -1);
    sarw_rule_t bad_rule = rule;
    sarw_tool_t bad_tool = tool;
    sarw_result_t r = result_at(NULL);
    sarw_location_t both;

    CHECK(sarw_create(NULL, NULL, NULL, NULL, NULL, &w) == SARW_ERR_ARG && w == NULL);
    w = writer_on(&s, -1);
    bad_rule.id = NULL;
    bad_tool.rules = &bad_rule;
    CHECK(sarw_run_begin(w, &bad_tool) == SARW_ERR_ARG && s.len == 0);
    bad_tool = tool;
    bad_tool.name = NULL;
    CHECK(sarw_run_begin(w, &bad_tool) == SARW_ERR_ARG && sarw_run_begin(w, NULL) == SARW_ERR_ARG);
    CHECK(sarw_run_begin(w, &tool) == SARW_OK);
    r.level = 9;
    CHECK(sarw_result(w, &r) == SARW_ERR_ARG);
    r = result_at(NULL);
    r.rule_index = -2;
    CHECK(sarw_result(w, &r) == SARW_ERR_ARG);
    memset(&both, 0, sizeof(both));
    both.path = "a";
    both.uri = "b";
    r = result_at(&both);
    CHECK(sarw_result(w, &r) == SARW_ERR_ARG);
    CHECK(sarw_run_end(w, NULL) == SARW_OK && sarw_finish(w) == SARW_OK);
    CHECK(json_valid(s.data, s.len) && strstr(s.data, "\"results\": []") != NULL);
    CHECK(sarw_strerror(SARW_ERR_STATE) != NULL && sarw_strerror(99) != NULL);
    sarw_destroy(w);
    sarw_destroy(NULL);
    free(s.data);
}

static void test_reused_buffer(void)
{
    sink_t s;
    sarw_writer_t *w = writer_on(&s, -1);
    char path[16];
    sarw_location_t loc;
    sarw_result_t r;

    memset(&loc, 0, sizeof(loc));
    loc.path = path;
    r = result_at(&loc);
    CHECK(sarw_run_begin(w, &tool) == SARW_OK);
    strcpy(path, "first");
    CHECK(sarw_result(w, &r) == SARW_OK);
    strcpy(path, "second");
    CHECK(sarw_result(w, &r) == SARW_OK);
    CHECK(sarw_run_end(w, NULL) == SARW_OK && sarw_finish(w) == SARW_OK);
    CHECK(strstr(s.data, "\"uri\": \"first\"") != NULL && strstr(s.data, "\"uri\": \"second\"") != NULL);
    sarw_destroy(w);
    free(s.data);
}

enum { OP_BEGIN, OP_RESULT, OP_END, OP_FINISH, OPS };

static int op_call(sarw_writer_t *w, int op)
{
    sarw_result_t r = result_at(NULL);

    switch (op) {
    case OP_BEGIN:
        return sarw_run_begin(w, &tool);
    case OP_RESULT:
        return sarw_result(w, &r);
    case OP_END:
        return sarw_run_end(w, NULL);
    default:
        return sarw_finish(w);
    }
}

static int op_next(int state, int op)
{
    static const int next[4][OPS] = {{1, -1, -1, -1}, {-1, 1, 2, -1}, {1, -1, -1, 3}, {-1, -1, -1, -1}};

    return next[state][op];
}

static int replay(sink_t *s, const int *seq, int n, int only_valid)
{
    static const int finish[4][4] = {{OP_BEGIN, OP_END, OP_FINISH, -1}, {OP_END, OP_FINISH, -1, -1},
                                     {OP_FINISH, -1, -1, -1}, {-1, -1, -1, -1}};
    sarw_writer_t *w = writer_on(s, -1);
    int state = 0, i, next, status;

    for (i = 0; i < n; i++) {
        next = op_next(state, seq[i]);
        if (only_valid && next < 0)
            continue;
        status = op_call(w, seq[i]);
        CHECK(next < 0 ? status == SARW_ERR_STATE : status == SARW_OK);
        if (next >= 0)
            state = next;
    }
    for (i = 0; finish[state][i] >= 0 && i < 4; i++)
        CHECK(op_call(w, finish[state][i]) == SARW_OK);
    sarw_destroy(w);
    return state;
}

static void test_sequences(void)
{
    int seq[6], n, i, code, total, count = 0;
    sink_t a, b;

    for (n = 1; n <= 6; n++) {
        for (total = 1, i = 0; i < n; i++)
            total *= OPS;
        for (code = 0; code < total; code++) {
            int c = code;

            for (i = 0; i < n; i++, c /= OPS)
                seq[i] = c % OPS;
            replay(&a, seq, n, 0);
            replay(&b, seq, n, 1);
            CHECK(json_valid(a.data, a.len) && a.len == b.len && memcmp(a.data, b.data, a.len) == 0);
            free(a.data);
            free(b.data);
            count++;
        }
    }
    CHECK(count == 4 + 16 + 64 + 256 + 1024 + 4096);
}

static int big_document(sarw_writer_t *w, int results)
{
    sarw_result_t r = result_at(NULL);
    int status = sarw_run_begin(w, &tool), i;

    for (i = 0; i < results && status == SARW_OK; i++)
        status = sarw_result(w, &r);
    if (status == SARW_OK)
        status = sarw_run_end(w, NULL);
    return status == SARW_OK ? sarw_finish(w) : status;
}

static void test_write_failure(void)
{
    sink_t full, s;
    sarw_writer_t *w = writer_on(&full, -1);
    long calls, k;

    CHECK(big_document(w, 300) == SARW_OK);
    sarw_destroy(w);
    for (calls = 0, k = 0; k < 1000; k++) {
        w = writer_on(&s, k);
        if (big_document(w, 300) == SARW_OK) {
            CHECK(s.len == full.len && memcmp(s.data, full.data, s.len) == 0);
            sarw_destroy(w);
            free(s.data);
            break;
        }
        CHECK(sarw_finish(w) == SARW_ERR_WRITE && sarw_run_begin(w, &tool) == SARW_ERR_WRITE);
        CHECK(s.len <= full.len && (s.len == 0 || memcmp(s.data, full.data, s.len) == 0));
        sarw_destroy(w);
        free(s.data);
        calls++;
    }
    CHECK(calls >= 10 && k < 1000);
    free(full.data);
}

typedef struct {
    int remaining;
    long live;
    size_t bytes;
    size_t peak;
} counting_alloc_t;

static void *counting_alloc(void *ctx, size_t size)
{
    counting_alloc_t *a = ctx;
    size_t *block;

    if (a->remaining-- == 0 || (block = malloc(size + sizeof(size_t))) == NULL)
        return NULL;
    *block = size;
    a->live++;
    if ((a->bytes += size) > a->peak)
        a->peak = a->bytes;
    return block + 1;
}

static void counting_free(void *ctx, void *ptr)
{
    counting_alloc_t *a = ctx;
    size_t *block = (size_t *)ptr - 1;

    a->live--;
    a->bytes -= *block;
    free(block);
}

static int discard(void *ctx, const char *data, size_t len)
{
    (void)data;
    *(size_t *)ctx += len;
    return 0;
}

static size_t peak_for(int results)
{
    counting_alloc_t a = {-1, 0, 0, 0};
    sarw_writer_t *w = NULL;
    size_t written = 0;

    CHECK(sarw_create(discard, &written, counting_alloc, counting_free, &a, &w) == SARW_OK);
    CHECK(big_document(w, results) == SARW_OK);
    sarw_destroy(w);
    CHECK(a.live == 0 && written > 0);
    return a.peak;
}

static void test_memory(void)
{
    counting_alloc_t a = {0, 0, 0, 0};
    sarw_writer_t *w = NULL;
    size_t written = 0;

    CHECK(sarw_create(discard, &written, counting_alloc, counting_free, &a, &w) == SARW_ERR_NOMEM && w == NULL);
    CHECK(a.live == 0);
    CHECK(sarw_create(discard, &written, counting_alloc, NULL, &a, &w) == SARW_ERR_ARG);
    CHECK(peak_for(10) == peak_for(100000));
}

int main(void)
{
    test_golden();
    test_escape();
    test_uri();
    test_tail();
    test_arguments();
    test_reused_buffer();
    test_sequences();
    test_write_failure();
    test_memory();
    puts("ok");
    return 0;
}
