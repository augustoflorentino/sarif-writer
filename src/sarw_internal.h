#ifndef SARW_INTERNAL_H
#define SARW_INTERNAL_H

#include "sarif-writer/sarif-writer.h"

#if defined(SARW_STATIC) && defined(__GNUC__)
#define SARW_INTERN static __attribute__((unused))
#elif defined(SARW_STATIC)
#define SARW_INTERN static
#else
#define SARW_INTERN
#endif

#define SARW_DEPTH 16
#define SARW_BUFFER 4096
#define SARW_MAX_PATH 4096
#define SARW_MAX_SEGMENTS (SARW_MAX_PATH / 2 + 1)

enum { SARW_CREATED, SARW_IN_RUN, SARW_RUN_DONE, SARW_FINISHED, SARW_FAILED };

typedef struct sarw_segment {
    uint16_t at;
    uint16_t len;
} sarw_segment_t;

typedef struct sarw_path {
    sarw_segment_t seg[SARW_MAX_SEGMENTS];
    size_t count;
    int absolute;
    int drive;
} sarw_path_t;

struct sarw_writer {
    sarw_write_fn write_fn;
    void *write_ctx;
    sarw_free_fn free_fn;
    void *alloc_ctx;
    int state;
    unsigned warnings;
    int depth;
    unsigned char has_items[SARW_DEPTH];
    size_t len;
    char buf[SARW_BUFFER];
    sarw_path_t path;
    const char *path_of;
    int path_relative;
};

SARW_INTERN void sarw_raw(sarw_writer_t *w, const char *s, size_t n);
SARW_INTERN int sarw_flush(sarw_writer_t *w);
SARW_INTERN void sarw_open(sarw_writer_t *w, char ch);
SARW_INTERN void sarw_close(sarw_writer_t *w, char ch);
SARW_INTERN void sarw_item(sarw_writer_t *w);
SARW_INTERN void sarw_key(sarw_writer_t *w, const char *key);
SARW_INTERN void sarw_string(sarw_writer_t *w, const char *s);
SARW_INTERN void sarw_kv_str(sarw_writer_t *w, const char *key, const char *value);
SARW_INTERN void sarw_kv_uint(sarw_writer_t *w, const char *key, uint64_t value);
SARW_INTERN void sarw_kv_text(sarw_writer_t *w, const char *key, const char *text);
SARW_INTERN void sarw_open_key(sarw_writer_t *w, const char *key, char ch);
SARW_INTERN void sarw_props(sarw_writer_t *w, const sarw_prop_t *props, size_t count);

SARW_INTERN int sarw_path_parse(sarw_path_t *p, const char *path, int relative_only);
SARW_INTERN int sarw_path_cached(sarw_writer_t *w, const char *path, int relative_only);
SARW_INTERN void sarw_path_write(sarw_writer_t *w, const char *path, const sarw_path_t *p);

#endif
