#include "sarw_internal.h"

#include <stdlib.h>
#include <string.h>

#define SARW_SCHEMA "https://json.schemastore.org/sarif-2.1.0.json"

static void *sarw_default_alloc(void *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}

static void sarw_default_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

int sarw_create(sarw_write_fn write_fn, void *write_ctx, sarw_alloc_fn alloc_fn, sarw_free_fn free_fn,
                void *alloc_ctx, sarw_writer_t **out_writer)
{
    sarw_writer_t *w;

    if (out_writer == NULL)
        return SARW_ERR_ARG;
    *out_writer = NULL;
    if (write_fn == NULL || (alloc_fn == NULL) != (free_fn == NULL))
        return SARW_ERR_ARG;
    if (alloc_fn == NULL) {
        alloc_fn = sarw_default_alloc;
        free_fn = sarw_default_free;
    }
    if ((w = alloc_fn(alloc_ctx, sizeof(*w))) == NULL)
        return SARW_ERR_NOMEM;
    memset(w, 0, sizeof(*w));
    w->write_fn = write_fn;
    w->write_ctx = write_ctx;
    w->free_fn = free_fn;
    w->alloc_ctx = alloc_ctx;
    w->state = SARW_CREATED;
    *out_writer = w;
    return SARW_OK;
}

void sarw_destroy(sarw_writer_t *writer)
{
    if (writer != NULL)
        writer->free_fn(writer->alloc_ctx, writer);
}

unsigned sarw_warnings(const sarw_writer_t *writer)
{
    return writer != NULL ? writer->warnings : 0;
}

const char *sarw_strerror(int status)
{
    switch (status) {
    case SARW_OK:
        return "ok";
    case SARW_ERR_ARG:
        return "invalid argument";
    case SARW_ERR_NOMEM:
        return "out of memory";
    case SARW_ERR_STATE:
        return "call out of order";
    case SARW_ERR_WRITE:
        return "write callback failed";
    default:
        return "unknown error";
    }
}

static int sarw_level_ok(int level)
{
    return level >= SARW_LEVEL_UNSET && level <= SARW_LEVEL_ERROR;
}

static int sarw_props_ok(const sarw_prop_t *props, size_t count)
{
    size_t i;

    if (count > 0 && props == NULL)
        return 0;
    for (i = 0; i < count; i++)
        if (props[i].key == NULL || props[i].value == NULL)
            return 0;
    return 1;
}

static int sarw_rule_ok(const sarw_rule_t *r)
{
    size_t i;

    if (r->id == NULL || !sarw_level_ok(r->level) || (r->tag_count > 0 && r->tags == NULL))
        return 0;
    for (i = 0; i < r->tag_count; i++)
        if (r->tags[i] == NULL)
            return 0;
    return sarw_props_ok(r->props, r->prop_count);
}

static int sarw_location_ok(sarw_writer_t *w, const sarw_location_t *l)
{
    if (l->path != NULL && l->uri != NULL)
        return 0;
    if (l->uri_base_id != NULL && l->path == NULL && l->uri == NULL)
        return 0;
    return l->path == NULL || sarw_path_cached(w, l->path, l->uri_base_id != NULL) == SARW_OK;
}

static int sarw_locations_ok(sarw_writer_t *w, const sarw_location_t *l, size_t count)
{
    size_t i;

    if (count > 0 && l == NULL)
        return 0;
    for (i = 0; i < count; i++)
        if (!sarw_location_ok(w, &l[i]))
            return 0;
    return 1;
}

static int sarw_result_ok(sarw_writer_t *w, const sarw_result_t *r)
{
    return r->rule_id != NULL && r->message != NULL && r->rule_index >= -1 && sarw_level_ok(r->level) &&
           sarw_locations_ok(w, r->locations, r->location_count) &&
           sarw_locations_ok(w, r->related, r->related_count) &&
           sarw_props_ok(r->fingerprints, r->fingerprint_count) && sarw_props_ok(r->props, r->prop_count);
}

static int sarw_tool_ok(const sarw_tool_t *t)
{
    size_t i;

    if (t->name == NULL || (t->rule_count > 0 && t->rules == NULL))
        return 0;
    for (i = 0; i < t->rule_count; i++)
        if (!sarw_rule_ok(&t->rules[i]))
            return 0;
    return 1;
}

static int sarw_tail_ok(sarw_writer_t *w, const sarw_run_tail_t *t)
{
    const sarw_invocation_t *inv = t->invocation;
    size_t i;

    if (!sarw_locations_ok(w, t->artifacts, t->artifact_count))
        return 0;
    for (i = 0; i < t->artifact_count; i++)
        if (t->artifacts[i].path == NULL && t->artifacts[i].uri == NULL)
            return 0;
    if (inv == NULL)
        return 1;
    if (inv->notification_count > 0 && inv->notifications == NULL)
        return 0;
    for (i = 0; i < inv->notification_count; i++)
        if (inv->notifications[i].message == NULL || !sarw_level_ok(inv->notifications[i].level))
            return 0;
    return 1;
}

static int sarw_gate(const sarw_writer_t *w, int want, int also)
{
    if (w == NULL)
        return SARW_ERR_ARG;
    if (w->state == SARW_FAILED)
        return SARW_ERR_WRITE;
    return w->state == want || w->state == also ? SARW_OK : SARW_ERR_STATE;
}

static int sarw_done(sarw_writer_t *w, int next)
{
    if (w->state == SARW_FAILED)
        return SARW_ERR_WRITE;
    w->state = next;
    return SARW_OK;
}

static void sarw_level(sarw_writer_t *w, int level)
{
    static const char *const names[] = {NULL, "none", "note", "warning", "error"};

    sarw_kv_str(w, "level", names[level]);
}

static void sarw_rule(sarw_writer_t *w, const sarw_rule_t *r)
{
    size_t i;

    sarw_item(w);
    sarw_open(w, '{');
    sarw_kv_str(w, "id", r->id);
    sarw_kv_str(w, "name", r->name);
    sarw_kv_text(w, "shortDescription", r->short_description);
    sarw_kv_text(w, "fullDescription", r->full_description);
    sarw_kv_text(w, "help", r->help_text);
    if (r->level != SARW_LEVEL_UNSET) {
        sarw_open_key(w, "defaultConfiguration", '{');
        sarw_level(w, r->level);
        sarw_close(w, '}');
    }
    if (r->tag_count > 0 || r->prop_count > 0) {
        sarw_open_key(w, "properties", '{');
        if (r->tag_count > 0) {
            sarw_open_key(w, "tags", '[');
            for (i = 0; i < r->tag_count; i++) {
                sarw_item(w);
                sarw_string(w, r->tags[i]);
            }
            sarw_close(w, ']');
        }
        sarw_props(w, r->props, r->prop_count);
        sarw_close(w, '}');
    }
    sarw_kv_str(w, "helpUri", r->help_uri);
    sarw_close(w, '}');
}

static void sarw_driver(sarw_writer_t *w, const sarw_tool_t *t)
{
    size_t i;

    sarw_open_key(w, "tool", '{');
    sarw_open_key(w, "driver", '{');
    sarw_kv_str(w, "name", t->name);
    sarw_kv_str(w, "version", t->version);
    sarw_kv_str(w, "informationUri", t->information_uri);
    if (t->rule_count > 0) {
        sarw_open_key(w, "rules", '[');
        for (i = 0; i < t->rule_count; i++)
            sarw_rule(w, &t->rules[i]);
        sarw_close(w, ']');
    }
    sarw_close(w, '}');
    sarw_close(w, '}');
}

int sarw_run_begin(sarw_writer_t *writer, const sarw_tool_t *tool)
{
    int status = sarw_gate(writer, SARW_CREATED, SARW_RUN_DONE);

    if (status != SARW_OK)
        return status;
    if (tool == NULL || !sarw_tool_ok(tool))
        return SARW_ERR_ARG;
    if (writer->state == SARW_CREATED) {
        sarw_open(writer, '{');
        sarw_kv_str(writer, "$schema", SARW_SCHEMA);
        sarw_kv_str(writer, "version", "2.1.0");
        sarw_open_key(writer, "runs", '[');
    }
    sarw_item(writer);
    sarw_open(writer, '{');
    sarw_driver(writer, tool);
    sarw_open_key(writer, "results", '[');
    return sarw_done(writer, SARW_IN_RUN);
}

static void sarw_artifact_location(sarw_writer_t *w, const char *key, const sarw_location_t *l)
{
    sarw_open_key(w, key, '{');
    if (l->uri != NULL) {
        sarw_kv_str(w, "uri", l->uri);
    } else {
        sarw_path_cached(w, l->path, l->uri_base_id != NULL);
        sarw_key(w, "uri");
        sarw_path_write(w, l->path, &w->path);
    }
    sarw_kv_str(w, "uriBaseId", l->uri_base_id);
    sarw_close(w, '}');
}

static void sarw_region(sarw_writer_t *w, const sarw_location_t *l)
{
    if (l->start_line == 0 && l->start_column == 0 && l->end_line == 0 && l->end_column == 0 &&
        !l->has_byte_offset && l->byte_length == 0)
        return;
    sarw_open_key(w, "region", '{');
    if (l->start_line > 0)
        sarw_kv_uint(w, "startLine", l->start_line);
    if (l->start_column > 0)
        sarw_kv_uint(w, "startColumn", l->start_column);
    if (l->end_line > 0)
        sarw_kv_uint(w, "endLine", l->end_line);
    if (l->end_column > 0)
        sarw_kv_uint(w, "endColumn", l->end_column);
    if (l->has_byte_offset)
        sarw_kv_uint(w, "byteOffset", l->byte_offset);
    if (l->byte_length > 0)
        sarw_kv_uint(w, "byteLength", l->byte_length);
    sarw_close(w, '}');
}

static void sarw_location(sarw_writer_t *w, const sarw_location_t *l)
{
    sarw_item(w);
    sarw_open(w, '{');
    if (l->path != NULL || l->uri != NULL) {
        sarw_open_key(w, "physicalLocation", '{');
        sarw_artifact_location(w, "artifactLocation", l);
        sarw_region(w, l);
        sarw_close(w, '}');
    }
    if (l->logical_name != NULL) {
        sarw_open_key(w, "logicalLocations", '[');
        sarw_item(w);
        sarw_open(w, '{');
        sarw_kv_str(w, "fullyQualifiedName", l->logical_name);
        sarw_close(w, '}');
        sarw_close(w, ']');
    }
    sarw_kv_text(w, "message", l->message);
    sarw_close(w, '}');
}

static void sarw_locations(sarw_writer_t *w, const char *key, const sarw_location_t *l, size_t count)
{
    size_t i;

    if (count == 0)
        return;
    sarw_open_key(w, key, '[');
    for (i = 0; i < count; i++)
        sarw_location(w, &l[i]);
    sarw_close(w, ']');
}

static void sarw_prop_object(sarw_writer_t *w, const char *key, const sarw_prop_t *props, size_t count)
{
    if (count == 0)
        return;
    sarw_open_key(w, key, '{');
    sarw_props(w, props, count);
    sarw_close(w, '}');
}

int sarw_result(sarw_writer_t *writer, const sarw_result_t *result)
{
    int status = sarw_gate(writer, SARW_IN_RUN, SARW_IN_RUN);

    if (status != SARW_OK)
        return status;
    writer->path_of = NULL;
    if (result == NULL || !sarw_result_ok(writer, result))
        return SARW_ERR_ARG;
    sarw_item(writer);
    sarw_open(writer, '{');
    sarw_kv_str(writer, "ruleId", result->rule_id);
    if (result->rule_index >= 0)
        sarw_kv_uint(writer, "ruleIndex", (uint64_t)result->rule_index);
    sarw_level(writer, result->level);
    sarw_kv_text(writer, "message", result->message);
    sarw_locations(writer, "locations", result->locations, result->location_count);
    sarw_locations(writer, "relatedLocations", result->related, result->related_count);
    sarw_prop_object(writer, "partialFingerprints", result->fingerprints, result->fingerprint_count);
    sarw_prop_object(writer, "properties", result->props, result->prop_count);
    sarw_close(writer, '}');
    return sarw_done(writer, SARW_IN_RUN);
}

static void sarw_artifacts(sarw_writer_t *w, const sarw_location_t *l, size_t count)
{
    size_t i;

    if (count == 0)
        return;
    sarw_open_key(w, "artifacts", '[');
    for (i = 0; i < count; i++) {
        sarw_item(w);
        sarw_open(w, '{');
        sarw_artifact_location(w, "location", &l[i]);
        sarw_close(w, '}');
    }
    sarw_close(w, ']');
}

static void sarw_invocation(sarw_writer_t *w, const sarw_invocation_t *inv)
{
    size_t i;

    sarw_open_key(w, "invocations", '[');
    sarw_item(w);
    sarw_open(w, '{');
    sarw_kv_str(w, "commandLine", inv->command_line);
    sarw_key(w, "executionSuccessful");
    sarw_raw(w, inv->execution_successful ? "true" : "false", inv->execution_successful ? 4 : 5);
    if (inv->notification_count > 0) {
        sarw_open_key(w, "toolExecutionNotifications", '[');
        for (i = 0; i < inv->notification_count; i++) {
            sarw_item(w);
            sarw_open(w, '{');
            sarw_level(w, inv->notifications[i].level);
            sarw_kv_text(w, "message", inv->notifications[i].message);
            sarw_close(w, '}');
        }
        sarw_close(w, ']');
    }
    sarw_close(w, '}');
    sarw_close(w, ']');
}

int sarw_run_end(sarw_writer_t *writer, const sarw_run_tail_t *tail)
{
    int status = sarw_gate(writer, SARW_IN_RUN, SARW_IN_RUN);

    if (status != SARW_OK)
        return status;
    writer->path_of = NULL;
    if (tail != NULL && !sarw_tail_ok(writer, tail))
        return SARW_ERR_ARG;
    sarw_close(writer, ']');
    if (tail != NULL) {
        sarw_artifacts(writer, tail->artifacts, tail->artifact_count);
        if (tail->invocation != NULL)
            sarw_invocation(writer, tail->invocation);
    }
    sarw_close(writer, '}');
    return sarw_done(writer, SARW_RUN_DONE);
}

int sarw_finish(sarw_writer_t *writer)
{
    int status = sarw_gate(writer, SARW_RUN_DONE, SARW_RUN_DONE);

    if (status != SARW_OK)
        return status;
    sarw_close(writer, ']');
    sarw_close(writer, '}');
    sarw_raw(writer, "\n", 1);
    if ((status = sarw_flush(writer)) != SARW_OK)
        return status;
    return sarw_done(writer, SARW_FINISHED);
}
