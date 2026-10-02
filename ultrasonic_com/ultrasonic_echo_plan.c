/* Bounded JSON reader for Auth's verification plan, for the ULTRASOUND
 * CO_LOCATION method. Same tokenizer as ir_com/ir_hk_plan.c; fields are
 * looked up only in their owning object, never by substring search. */
#include <ctype.h>
#include <string.h>

#include "ultrasonic_echo.h"

typedef struct {
    const char *start, *end;
    int next;
    char type;
} token;
typedef struct {
    const char* p;
    token t[256];
    int count;
} parser;
static void space(parser* p) {
    while (isspace((unsigned char)*p->p)) ++p->p;
}
static int value(parser* p, unsigned depth) {
    space(p);
    if (depth > 16 || p->count == 256 || !*p->p) return -1;
    int i = p->count++;
    token* t = &p->t[i];
    t->start = p->p;
    t->type = *p->p;
    if (*p->p == '{' || *p->p == '[') {
        char close = *p->p++ == '{' ? '}' : ']';
        space(p);
        if (*p->p != close)
            for (;;) {
                if (close == '}') {
                    space(p);
                    if (*p->p != '"' || value(p, depth + 1) < 0) return -1;
                    space(p);
                    if (*p->p++ != ':') return -1;
                }
                if (value(p, depth + 1) < 0) return -1;
                space(p);
                if (*p->p == close) break;
                if (*p->p++ != ',') return -1;
            }
        ++p->p;
    } else if (*p->p == '"') {
        ++p->p;
        while (*p->p && *p->p != '"') {
            if ((unsigned char)*p->p < 32) return -1;
            if (*p->p++ == '\\') {
                if (*p->p == 'u') {
                    ++p->p;
                    for (int j = 0; j < 4; ++j)
                        if (!isxdigit((unsigned char)*p->p++)) return -1;
                } else if (*p->p && strchr("\"\\/bfnrt", *p->p))
                    ++p->p;
                else
                    return -1;
            }
        }
        if (*p->p++ != '"') return -1;
    } else if (*p->p == '-' || isdigit((unsigned char)*p->p)) {
        t->type = 'n';
        if (*p->p == '-') ++p->p;
        if (*p->p == '0')
            ++p->p;
        else {
            if (!isdigit((unsigned char)*p->p)) return -1;
            while (isdigit((unsigned char)*p->p)) ++p->p;
        }
        if (*p->p == '.') {
            ++p->p;
            if (!isdigit((unsigned char)*p->p)) return -1;
            while (isdigit((unsigned char)*p->p)) ++p->p;
        }
        if (*p->p == 'e' || *p->p == 'E') {
            ++p->p;
            if (*p->p == '+' || *p->p == '-') ++p->p;
            if (!isdigit((unsigned char)*p->p)) return -1;
            while (isdigit((unsigned char)*p->p)) ++p->p;
        }
    } else {
        const char* word = *p->p == 't'   ? "true"
                           : *p->p == 'f' ? "false"
                                          : "null";
        if (strncmp(p->p, word, strlen(word))) return -1;
        p->p += strlen(word);
    }
    t->end = p->p;
    t->next = p->count;
    return i;
}
static int eq(const token* t, const char* s) {
    return t->type == '"' && (size_t)(t->end - t->start) == strlen(s) + 2 &&
           !memcmp(t->start + 1, s, strlen(s));
}
static int field(const parser* p, int object, const char* name) {
    if (object < 0 || p->t[object].type != '{') return -1;
    int found = -1;
    for (int i = object + 1; i < p->t[object].next;) {
        int v = i + 1;
        if (eq(&p->t[i], name)) {
            if (found >= 0) return -2;
            found = v;
        }
        i = p->t[v].next;
    }
    return found;
}
/* Non-negative JSON integer within [min, max]; fractions/exponents reject. */
static int integer(const parser* p, int i, unsigned min, unsigned max,
                   unsigned* out) {
    if (i < 0 || p->t[i].type != 'n') return -1;
    unsigned long long v = 0;
    for (const char* s = p->t[i].start; s < p->t[i].end; ++s) {
        if (!isdigit((unsigned char)*s)) return -1;
        v = v * 10 + (unsigned)(*s - '0');
        if (v > max) return -1;
    }
    if (p->t[i].end == p->t[i].start || v < min) return -1;
    *out = (unsigned)v;
    return 0;
}
/* Entity names never need escapes; reject them rather than unescape. */
static int entity_name(const parser* p, int i, char* out, size_t capacity) {
    if (i < 0 || p->t[i].type != '"') return -1;
    const char* s = p->t[i].start + 1;
    size_t n = (size_t)(p->t[i].end - 1 - s);
    if (n == 0 || n >= capacity || memchr(s, '\\', n)) return -1;
    memcpy(out, s, n);
    out[n] = 0;
    return 0;
}
int ultrasonic_echo_plan_config(const char* plan, ultrasonic_echo_config* c,
                                ultrasonic_echo_identity* id) {
    if (!plan || !c || !id || strlen(plan) >= MAX_CHALLENGE_LENGTH) return -1;
    parser p = {.p = plan, .count = 0};
    if (value(&p, 0) != 0) return -1;
    space(&p);
    if (*p.p || p.t[0].type != '{') return -1;
    int required = field(&p, 0, "requiredChecks"), required_co = 0;
    if (required < 0 || p.t[required].type != '[') return -1;
    for (int i = required + 1; i < p.t[required].next; i = p.t[i].next) {
        if (p.t[i].type != '"') return -1;
        if (eq(&p.t[i], "CO_LOCATION")) required_co = 1;
    }
    int checks = field(&p, 0, "verificationPlan");
    if (checks < 0 || p.t[checks].type != '{') return -1;
    int co = field(&p, checks, "CO_LOCATION");
    if (co == -1 && !required_co) return 0;
    if (co < 0) return -1;
    int selected = field(&p, co, "selectedMethod");
    int method = field(&p, selected, "method");
    if (method < 0) return -1;
    if (eq(&p.t[method], "DUMMY")) return 0;
    int topology = field(&p, co, "topology");
    if (!eq(&p.t[method], "ULTRASOUND") || topology < 0 ||
        !eq(&p.t[topology], "MUTUAL"))
        return -1;
    int params = field(&p, selected, "parameters");
    if (params < 0 || p.t[params].type != '{') return -1;
    /* The old ULTRASOUND entry's round/delay fields are not echo settings;
     * a catalog still carrying them is rejected, not reinterpreted. */
    if (field(&p, params, "rounds") != -1 ||
        field(&p, params, "max_delay_us") != -1 ||
        field(&p, params, "success_threshold") != -1)
        return -1;
    if (integer(&p, field(&p, params, "max_response_us"), 1,
                ULTRASONIC_ECHO_MAX_RESPONSE_US_LIMIT, &c->max_response_us) ||
        integer(&p, field(&p, params, "response_timeout_ms"), 1,
                ULTRASONIC_ECHO_TIMEOUT_MS_LIMIT, &c->response_timeout_ms))
        return -1;
    /* A pairwise echo needs exactly one target, named by Auth. */
    int targets = field(&p, 0, "targets");
    if (targets < 0 || p.t[targets].type != '[' ||
        targets + 1 >= p.t[targets].next ||
        p.t[targets + 1].next != p.t[targets].next)
        return -1;
    if (entity_name(&p, field(&p, 0, "requester"), id->requester,
                    sizeof(id->requester)) ||
        entity_name(&p, targets + 1, id->target, sizeof(id->target)))
        return -1;
    return ultrasonic_echo_config_valid(c) ? 1 : -1;
}
