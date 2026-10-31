#include "sarw_internal.h"

#include <string.h>

static int sarw_is_drive(const char *s, size_t len)
{
    return len == 2 && s[1] == ':' && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z'));
}

static int sarw_path_add(sarw_path_t *p, const char *path, size_t at, size_t len)
{
    const char *s = path + at;

    if (len == 0 || (len == 1 && s[0] == '.'))
        return SARW_OK;
    if (len == 2 && s[0] == '.' && s[1] == '.') {
        if (p->count > (size_t)p->drive) {
            p->count--;
            return SARW_OK;
        }
        return p->absolute ? SARW_OK : SARW_ERR_ARG;
    }
    p->seg[p->count].at = (uint16_t)at;
    p->seg[p->count].len = (uint16_t)len;
    p->count++;
    return SARW_OK;
}

int sarw_path_parse(sarw_path_t *p, const char *path, int relative_only)
{
    size_t len = strlen(path), at = 0, end;
    int status = SARW_OK;

    p->count = 0;
    p->drive = 0;
    if (len == 0 || len > SARW_MAX_PATH)
        return SARW_ERR_ARG;
    p->absolute = path[0] == '/' || path[0] == '\\';
    end = strcspn(path, "/\\");
    if (sarw_is_drive(path, end)) {
        p->absolute = p->drive = 1;
        status = sarw_path_add(p, path, 0, 2);
        at = end;
    }
    if (p->absolute && relative_only)
        return SARW_ERR_ARG;
    while (status == SARW_OK && at <= len) {
        end = at + strcspn(path + at, "/\\");
        status = sarw_path_add(p, path, at, end - at);
        at = end + 1;
    }
    return status == SARW_OK && p->count == 0 && !p->absolute ? SARW_ERR_ARG : status;
}

int sarw_path_cached(sarw_writer_t *w, const char *path, int relative_only)
{
    int status;

    if (w->path_of == path && w->path_relative == relative_only)
        return SARW_OK;
    w->path_of = NULL;
    if ((status = sarw_path_parse(&w->path, path, relative_only)) == SARW_OK) {
        w->path_of = path;
        w->path_relative = relative_only;
    }
    return status;
}

static int sarw_plain(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c != 0 && strchr("-._~!$&'()*+,;=@", c) != NULL);
}

static void sarw_encode(sarw_writer_t *w, const char *s, size_t len)
{
    static const char hex[] = "0123456789ABCDEF";
    const unsigned char *p = (const unsigned char *)s;
    char esc[3] = {'%', 0, 0};
    size_t i, run = 0;

    for (i = 0; i < len; i++) {
        if (sarw_plain(p[i]))
            continue;
        sarw_raw(w, s + run, i - run);
        esc[1] = hex[p[i] >> 4];
        esc[2] = hex[p[i] & 15];
        sarw_raw(w, esc, 3);
        run = i + 1;
    }
    sarw_raw(w, s + run, len - run);
}

void sarw_path_write(sarw_writer_t *w, const char *path, const sarw_path_t *p)
{
    size_t i;

    sarw_raw(w, "\"", 1);
    if (p->absolute)
        sarw_raw(w, "file:///", 8);
    for (i = 0; i < p->count; i++) {
        if (i > 0)
            sarw_raw(w, "/", 1);
        if (i == 0 && p->drive)
            sarw_raw(w, path + p->seg[i].at, 2);
        else
            sarw_encode(w, path + p->seg[i].at, p->seg[i].len);
    }
    sarw_raw(w, "\"", 1);
}
