#include "sarif-writer/sarif-writer.h"

#include <stdio.h>
#include <string.h>

static int to_stdout(void *ctx, const char *data, size_t len)
{
    (void)ctx;
    return fwrite(data, 1, len, stdout) == len ? 0 : 1;
}

int main(void)
{
    static const char *const tags[] = {"security", "external/cwe/cwe-798"};
    static const sarw_prop_t severity[] = {{"security-severity", "8.0"}};
    sarw_prop_t fingerprint = {"hello/v1", "4f1c"};
    sarw_rule_t rule;
    sarw_tool_t tool;
    sarw_location_t where;
    sarw_result_t result;
    sarw_writer_t *w = NULL;
    int status;

    memset(&rule, 0, sizeof(rule));
    rule.id = "HELLO-001";
    rule.name = "HardcodedPassword";
    rule.short_description = "Hard-coded password";
    rule.level = SARW_LEVEL_ERROR;
    rule.tags = tags;
    rule.tag_count = 2;
    rule.props = severity;
    rule.prop_count = 1;

    memset(&tool, 0, sizeof(tool));
    tool.name = "hello";
    tool.version = "1.0.0";
    tool.rules = &rule;
    tool.rule_count = 1;

    memset(&where, 0, sizeof(where));
    where.path = "etc/config.ini";
    where.uri_base_id = "SRCROOT";
    where.start_line = 12;

    memset(&result, 0, sizeof(result));
    result.rule_id = "HELLO-001";
    result.rule_index = 0;
    result.level = SARW_LEVEL_ERROR;
    result.message = "Password set in plain text";
    result.locations = &where;
    result.location_count = 1;
    result.fingerprints = &fingerprint;
    result.fingerprint_count = 1;

    status = sarw_create(to_stdout, NULL, NULL, NULL, NULL, &w);
    if (status == SARW_OK)
        status = sarw_run_begin(w, &tool);
    if (status == SARW_OK)
        status = sarw_result(w, &result);
    if (status == SARW_OK)
        status = sarw_run_end(w, NULL);
    if (status == SARW_OK)
        status = sarw_finish(w);
    sarw_destroy(w);
    if (status != SARW_OK)
        fprintf(stderr, "sarif-hello: %s\n", sarw_strerror(status));
    return status == SARW_OK ? 0 : 1;
}
