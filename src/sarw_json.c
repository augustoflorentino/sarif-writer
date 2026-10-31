#include "sarw_internal.h"

#include <string.h>

int sarw_flush(sarw_writer_t *w)
{
    if (w->state == SARW_FAILED)
        return SARW_ERR_WRITE;
    if (w->len > 0 && w->write_fn(w->write_ctx, w->buf, w->len) != 0) {
        w->state = SARW_FAILED;
        return SARW_ERR_WRITE;
    }
    w->len = 0;
    return SARW_OK;
}

void sarw_raw(sarw_writer_t *w, const char *s, size_t n)
{
    size_t room;

    if (n <= SARW_BUFFER - w->len && w->state != SARW_FAILED) {
        memcpy(w->buf + w->len, s, n);
        w->len += n;
        return;
    }
    while (n > 0 && w->state != SARW_FAILED) {
        if (w->len == SARW_BUFFER && sarw_flush(w) != SARW_OK)
            return;
        room = SARW_BUFFER - w->len;
        if (room > n)
            room = n;
        memcpy(w->buf + w->len, s, room);
        w->len += room;
        s += room;
        n -= room;
    }
}

static void sarw_newline(sarw_writer_t *w)
{
    static const char line[] = "\n                                ";

    sarw_raw(w, line, 1 + 2 * (size_t)w->depth);
}

void sarw_item(sarw_writer_t *w)
{
    if (w->depth == 0)
        return;
    if (w->has_items[w->depth])
        sarw_raw(w, ",", 1);
    w->has_items[w->depth] = 1;
    sarw_newline(w);
}

void sarw_open(sarw_writer_t *w, char ch)
{
    sarw_raw(w, &ch, 1);
    w->depth++;
    w->has_items[w->depth] = 0;
}

void sarw_close(sarw_writer_t *w, char ch)
{
    int had = w->has_items[w->depth];

    w->depth--;
    if (had)
        sarw_newline(w);
    sarw_raw(w, &ch, 1);
}

static size_t sarw_utf8(const unsigned char *s)
{
    unsigned c = s[0];

    if (c >= 0xc2 && c <= 0xdf)
        return (s[1] & 0xc0) == 0x80 ? 2 : 0;
    if (c >= 0xe0 && c <= 0xef) {
        unsigned lo = c == 0xe0 ? 0xa0 : 0x80, hi = c == 0xed ? 0x9f : 0xbf;
        return s[1] >= lo && s[1] <= hi && (s[2] & 0xc0) == 0x80 ? 3 : 0;
    }
    if (c >= 0xf0 && c <= 0xf4) {
        unsigned lo = c == 0xf0 ? 0x90 : 0x80, hi = c == 0xf4 ? 0x8f : 0xbf;
        return s[1] >= lo && s[1] <= hi && (s[2] & 0xc0) == 0x80 && (s[3] & 0xc0) == 0x80 ? 4 : 0;
    }
    return 0;
}

static void sarw_escape(sarw_writer_t *w, unsigned char c)
{
    static const char hex[] = "0123456789abcdef";
    char out[6] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
    const char *named = c == '"' ? "\\\"" : c == '\\' ? "\\\\" : c == '\n' ? "\\n" : c == '\r' ? "\\r"
                      : c == '\t' ? "\\t" : c == '\b' ? "\\b" : c == '\f' ? "\\f" : NULL;

    if (named != NULL)
        sarw_raw(w, named, 2);
    else
        sarw_raw(w, out, 6);
}

void sarw_string(sarw_writer_t *w, const char *s)
{
    const unsigned char *p = (const unsigned char *)s, *run = p;
    size_t n;

    sarw_raw(w, "\"", 1);
    while (*p != 0) {
        if (*p >= 0x20 && *p < 0x80 && *p != '"' && *p != '\\') {
            p++;
            continue;
        }
        sarw_raw(w, (const char *)run, (size_t)(p - run));
        if (*p >= 0x80 && (n = sarw_utf8(p)) > 0) {
            sarw_raw(w, (const char *)p, n);
            p += n;
        } else if (*p >= 0x80) {
            sarw_raw(w, "\xef\xbf\xbd", 3);
            w->warnings |= SARW_WARN_UTF8;
            p++;
        } else {
            sarw_escape(w, *p++);
        }
        run = p;
    }
    sarw_raw(w, (const char *)run, (size_t)(p - run));
    sarw_raw(w, "\"", 1);
}

void sarw_key(sarw_writer_t *w, const char *key)
{
    sarw_item(w);
    sarw_raw(w, "\"", 1);
    sarw_raw(w, key, strlen(key));
    sarw_raw(w, "\": ", 3);
}

void sarw_kv_str(sarw_writer_t *w, const char *key, const char *value)
{
    if (value == NULL)
        return;
    sarw_key(w, key);
    sarw_string(w, value);
}

void sarw_kv_uint(sarw_writer_t *w, const char *key, uint64_t value)
{
    char digits[20];
    size_t n = sizeof(digits);

    do {
        digits[--n] = (char)('0' + value % 10);
        value /= 10;
    } while (value > 0);
    sarw_key(w, key);
    sarw_raw(w, digits + n, sizeof(digits) - n);
}

void sarw_open_key(sarw_writer_t *w, const char *key, char ch)
{
    sarw_key(w, key);
    sarw_open(w, ch);
}

void sarw_kv_text(sarw_writer_t *w, const char *key, const char *text)
{
    if (text == NULL)
        return;
    sarw_open_key(w, key, '{');
    sarw_kv_str(w, "text", text);
    sarw_close(w, '}');
}

void sarw_props(sarw_writer_t *w, const sarw_prop_t *props, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        sarw_item(w);
        sarw_string(w, props[i].key);
        sarw_raw(w, ": ", 2);
        sarw_string(w, props[i].value);
    }
}
