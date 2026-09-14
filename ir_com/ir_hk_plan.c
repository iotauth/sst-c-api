/* Bounded JSON reader for Auth's verification plan. Fields are looked up only
 * in their owning object, never by substring search across unrelated checks. */
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "ir_hk.h"

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
static int number(const parser* p, int i, unsigned scale, unsigned* out) {
    if (i < 0 || p->t[i].type != 'n') return -1;
    char* end;
    double d = strtod(p->t[i].start, &end) * scale;
    if (end != p->t[i].end || !isfinite(d) || d <= 0 || d > 1000000) return -1;
    unsigned n = (unsigned)(d + 0.5);
    if (fabs(d - n) > 0.0000001) return -1;
    *out = n;
    return 0;
}
int ir_hk_plan_config(const char* plan, ir_hk_config* c) {
    if (!plan || !c || strlen(plan) >= MAX_CHALLENGE_LENGTH) return -1;
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
    if (!eq(&p.t[method], "IR") || topology < 0 ||
        !eq(&p.t[topology], "MUTUAL"))
        return -1;
    int params = field(&p, selected, "parameters");
    if (number(&p, field(&p, params, "rounds"), 1, &c->rounds) ||
        number(&p, field(&p, params, "success_threshold"), 1000000,
               &c->threshold_ppm) ||
        number(&p, field(&p, params, "max_delay_us"), 1, &c->max_delay_us))
        return -1;
    return ir_hk_config_valid(c) ? 1 : -1;
}
