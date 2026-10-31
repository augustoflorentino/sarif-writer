#ifndef JSON_CHECK_H
#define JSON_CHECK_H

#include <stddef.h>
#include <string.h>

typedef struct {
    const unsigned char *p;
    const unsigned char *end;
    int depth;
} jc_t;

static int jc_value(jc_t *j);

static void jc_space(jc_t *j)
{
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\n' || *j->p == '\r' || *j->p == '\t'))
        j->p++;
}

static int jc_hex(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static size_t jc_utf8(const unsigned char *s, size_t left)
{
    unsigned c = s[0], lo = 0x80, hi = 0xbf;
    size_t n = c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0, i;

    if (n == 0 || n > left)
        return 0;
    lo = c == 0xe0 ? 0xa0 : c == 0xf0 ? 0x90 : 0x80;
    hi = c == 0xed ? 0x9f : c == 0xf4 ? 0x8f : 0xbf;
    if (s[1] < lo || s[1] > hi)
        return 0;
    for (i = 2; i < n; i++)
        if ((s[i] & 0xc0) != 0x80)
            return 0;
    return n;
}

static int jc_escape(jc_t *j)
{
    int i;

    if (j->p >= j->end)
        return 0;
    if (*j->p != 'u')
        return strchr("\"\\/bfnrt", *j->p++) != NULL && j->p[-1] != 0;
    if (j->end - j->p < 5)
        return 0;
    for (i = 1; i <= 4; i++)
        if (!jc_hex(j->p[i]))
            return 0;
    j->p += 5;
    return 1;
}

static int jc_string(jc_t *j)
{
    size_t n;

    j->p++;
    while (j->p < j->end && *j->p != '"') {
        if (*j->p < 0x20)
            return 0;
        if (*j->p == '\\') {
            j->p++;
            if (!jc_escape(j))
                return 0;
        } else if (*j->p >= 0x80) {
            if ((n = jc_utf8(j->p, (size_t)(j->end - j->p))) == 0)
                return 0;
            j->p += n;
        } else {
            j->p++;
        }
    }
    if (j->p >= j->end)
        return 0;
    j->p++;
    return 1;
}

static int jc_number(jc_t *j)
{
    const unsigned char *start;

    if (j->p < j->end && *j->p == '-')
        j->p++;
    if (j->p >= j->end || *j->p < '0' || *j->p > '9')
        return 0;
    if (*j->p == '0')
        j->p++;
    else
        while (j->p < j->end && *j->p >= '0' && *j->p <= '9')
            j->p++;
    if (j->p < j->end && *j->p == '.') {
        start = ++j->p;
        while (j->p < j->end && *j->p >= '0' && *j->p <= '9')
            j->p++;
        if (j->p == start)
            return 0;
    }
    return 1;
}

static int jc_literal(jc_t *j, const char *word)
{
    size_t n = strlen(word);

    if ((size_t)(j->end - j->p) < n || memcmp(j->p, word, n) != 0)
        return 0;
    j->p += n;
    return 1;
}

static int jc_container(jc_t *j, unsigned char close, int object)
{
    j->p++;
    if (++j->depth > 64)
        return 0;
    jc_space(j);
    if (j->p < j->end && *j->p == close) {
        j->p++;
        j->depth--;
        return 1;
    }
    for (;;) {
        jc_space(j);
        if (object) {
            if (j->p >= j->end || *j->p != '"' || !jc_string(j))
                return 0;
            jc_space(j);
            if (j->p >= j->end || *j->p++ != ':')
                return 0;
        }
        if (!jc_value(j))
            return 0;
        jc_space(j);
        if (j->p < j->end && *j->p == ',') {
            j->p++;
            continue;
        }
        if (j->p >= j->end || *j->p++ != close)
            return 0;
        j->depth--;
        return 1;
    }
}

static int jc_value(jc_t *j)
{
    jc_space(j);
    if (j->p >= j->end)
        return 0;
    switch (*j->p) {
    case '{':
        return jc_container(j, '}', 1);
    case '[':
        return jc_container(j, ']', 0);
    case '"':
        return jc_string(j);
    case 't':
        return jc_literal(j, "true");
    case 'f':
        return jc_literal(j, "false");
    case 'n':
        return jc_literal(j, "null");
    default:
        return jc_number(j);
    }
}

static int json_valid(const char *data, size_t len)
{
    jc_t j;

    j.p = (const unsigned char *)data;
    j.end = j.p + len;
    j.depth = 0;
    if (!jc_value(&j))
        return 0;
    jc_space(&j);
    return j.p == j.end;
}

#endif
