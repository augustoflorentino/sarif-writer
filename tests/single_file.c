#define SARW_IMPLEMENTATION
#include "sarif-writer/sarif-writer.h"

#include <string.h>

static int count(void *ctx, const char *data, size_t len)
{
    (void)data;
    *(size_t *)ctx += len;
    return 0;
}

int main(void)
{
    sarw_tool_t tool;
    sarw_result_t result;
    sarw_writer_t *w = NULL;
    size_t written = 0;
    int status;

    memset(&tool, 0, sizeof(tool));
    memset(&result, 0, sizeof(result));
    tool.name = "single";
    result.rule_id = "S1";
    result.rule_index = -1;
    result.message = "m";
    status = sarw_create(count, &written, NULL, NULL, NULL, &w);
    if (status == SARW_OK)
        status = sarw_run_begin(w, &tool);
    if (status == SARW_OK)
        status = sarw_result(w, &result);
    if (status == SARW_OK)
        status = sarw_run_end(w, NULL);
    if (status == SARW_OK)
        status = sarw_finish(w);
    if (sarw_strerror(status) == NULL || sarw_warnings(w) != 0)
        status = SARW_ERR_ARG;
    sarw_destroy(w);
    return status == SARW_OK && written > 0 ? 0 : 1;
}
