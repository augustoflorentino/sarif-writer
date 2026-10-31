#ifndef SARIF_WRITER_H
#define SARIF_WRITER_H

#include <stddef.h>
#include <stdint.h>

#if defined(SARW_STATIC) && defined(__GNUC__)
#define SARW_API static __attribute__((unused))
#elif defined(SARW_STATIC)
#define SARW_API static
#elif defined(_WIN32) && defined(SARW_BUILD_SHARED)
#define SARW_API __declspec(dllexport)
#elif defined(_WIN32) && defined(SARW_SHARED)
#define SARW_API __declspec(dllimport)
#elif defined(__GNUC__) && defined(SARW_BUILD_SHARED)
#define SARW_API __attribute__((visibility("default")))
#else
#define SARW_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SARW_OK 0
#define SARW_ERR_ARG 1
#define SARW_ERR_NOMEM 2
#define SARW_ERR_STATE 3
#define SARW_ERR_WRITE 4

#define SARW_WARN_UTF8 0x01u

#define SARW_LEVEL_UNSET 0
#define SARW_LEVEL_NONE 1
#define SARW_LEVEL_NOTE 2
#define SARW_LEVEL_WARNING 3
#define SARW_LEVEL_ERROR 4

typedef struct sarw_writer sarw_writer_t;

typedef void *(*sarw_alloc_fn)(void *ctx, size_t size);
typedef void (*sarw_free_fn)(void *ctx, void *ptr);
typedef int (*sarw_write_fn)(void *ctx, const char *data, size_t len);

typedef struct sarw_prop {
    const char *key;
    const char *value;
} sarw_prop_t;

typedef struct sarw_rule {
    const char *id;
    const char *name;
    const char *short_description;
    const char *full_description;
    const char *help_text;
    int level;
    const char *const *tags;
    size_t tag_count;
    const sarw_prop_t *props;
    size_t prop_count;
    const char *help_uri;
} sarw_rule_t;

typedef struct sarw_tool {
    const char *name;
    const char *version;
    const char *information_uri;
    const sarw_rule_t *rules;
    size_t rule_count;
} sarw_tool_t;

typedef struct sarw_location {
    const char *path;
    const char *uri;
    const char *uri_base_id;
    uint64_t start_line;
    uint64_t start_column;
    uint64_t end_line;
    uint64_t end_column;
    uint64_t byte_offset;
    uint64_t byte_length;
    int has_byte_offset;
    const char *logical_name;
    const char *message;
} sarw_location_t;

typedef struct sarw_result {
    const char *rule_id;
    int64_t rule_index;
    int level;
    const char *message;
    const sarw_location_t *locations;
    size_t location_count;
    const sarw_location_t *related;
    size_t related_count;
    const sarw_prop_t *fingerprints;
    size_t fingerprint_count;
    const sarw_prop_t *props;
    size_t prop_count;
} sarw_result_t;

typedef struct sarw_notification {
    const char *message;
    int level;
} sarw_notification_t;

typedef struct sarw_invocation {
    const char *command_line;
    int execution_successful;
    const sarw_notification_t *notifications;
    size_t notification_count;
} sarw_invocation_t;

typedef struct sarw_run_tail {
    const sarw_location_t *artifacts;
    size_t artifact_count;
    const sarw_invocation_t *invocation;
} sarw_run_tail_t;

SARW_API int sarw_create(sarw_write_fn write_fn, void *write_ctx, sarw_alloc_fn alloc_fn, sarw_free_fn free_fn,
                         void *alloc_ctx, sarw_writer_t **out_writer);
SARW_API void sarw_destroy(sarw_writer_t *writer);
SARW_API int sarw_run_begin(sarw_writer_t *writer, const sarw_tool_t *tool);
SARW_API int sarw_result(sarw_writer_t *writer, const sarw_result_t *result);
SARW_API int sarw_run_end(sarw_writer_t *writer, const sarw_run_tail_t *tail);
SARW_API int sarw_finish(sarw_writer_t *writer);
SARW_API unsigned sarw_warnings(const sarw_writer_t *writer);
SARW_API const char *sarw_strerror(int status);

#ifdef __cplusplus
}
#endif

#endif
