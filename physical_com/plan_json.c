/* Bounded JSON tokenizer for Auth's verification plan; see plan_json.h. */
#include "plan_json.h"

#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "../src/c_api.h"

static void space(plan_json* p) {
    while (isspace((unsigned char)*p->p)) ++p->p;
}
static int value(plan_json* p, unsigned depth) {
    space(p);
    if (depth > 16 || p->count == PLAN_JSON_MAX_TOKENS || !*p->p) return -1;
    int i = p->count++;
    plan_json_token* t = &p->t[i];
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
static int eq(const plan_json_token* t, const char* s) {
    return t->type == '"' && (size_t)(t->end - t->start) == strlen(s) + 2 &&
           !memcmp(t->start + 1, s, strlen(s));
}
int plan_json_field(const plan_json* p, int object, const char* name) {
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
/* JSON integer (optionally negative) within [min, max]; fractions and
 * exponents reject. */
int plan_json_is(const plan_json* j, int i, const char* s) {
    return i >= 0 && eq(&j->t[i], s);
}

int plan_json_int(const plan_json* j, int i, long min, long max, long* out) {
    if (i < 0 || j->t[i].type != 'n') return -1;
    const char* s = j->t[i].start;
    int negative = *s == '-';
    if (negative) ++s;
    if (s == j->t[i].end) return -1;
    long v = 0;
    for (; s < j->t[i].end; ++s) {
        if (!isdigit((unsigned char)*s)) return -1;
        v = v * 10 + (*s - '0');
        if (v > 1000000000L) return -1; /* beyond any plan parameter */
    }
    if (negative) v = -v;
    if (v < min || v > max) return -1;
    *out = v;
    return 0;
}

int plan_json_scaled(const plan_json* j, int i, unsigned scale, unsigned* out) {
    if (i < 0 || j->t[i].type != 'n') return -1;
    char* end;
    double d = strtod(j->t[i].start, &end) * scale;
    if (end != j->t[i].end || !isfinite(d) || d <= 0 || d > 1000000) return -1;
    unsigned n = (unsigned)(d + 0.5);
    if (fabs(d - n) > 0.0000001) return -1;
    *out = n;
    return 0;
}

int plan_json_name(const plan_json* j, int i, char* out, size_t capacity) {
    if (i < 0 || j->t[i].type != '"') return -1;
    const char* s = j->t[i].start + 1;
    size_t n = (size_t)(j->t[i].end - 1 - s);
    if (n == 0 || n >= capacity || memchr(s, '\\', n)) return -1;
    memcpy(out, s, n);
    out[n] = 0;
    return 0;
}

int plan_co_location(const char* plan, const char* method, plan_json* j,
                     int* params) {
    if (!plan || !method || !j || !params ||
        strlen(plan) >= MAX_CHALLENGE_LENGTH)
        return -1;
    j->p = plan;
    j->count = 0;
    if (value(j, 0) != 0) return -1;
    space(j);
    if (*j->p || j->t[0].type != '{') return -1;
    int required = plan_json_field(j, 0, "requiredChecks"), required_co = 0;
    if (required < 0 || j->t[required].type != '[') return -1;
    for (int i = required + 1; i < j->t[required].next; i = j->t[i].next) {
        if (j->t[i].type != '"') return -1;
        if (eq(&j->t[i], "CO_LOCATION")) required_co = 1;
    }
    int checks = plan_json_field(j, 0, "verificationPlan");
    if (checks < 0 || j->t[checks].type != '{') return -1;
    int co = plan_json_field(j, checks, "CO_LOCATION");
    if (co == -1 && !required_co) return 0;
    if (co < 0) return -1;
    int selected = plan_json_field(j, co, "selectedMethod");
    int m = plan_json_field(j, selected, "method");
    if (m < 0) return -1;
    if (eq(&j->t[m], "DUMMY")) return 0;
    int topology = plan_json_field(j, co, "topology");
    if (!eq(&j->t[m], method) || topology < 0 || !eq(&j->t[topology], "MUTUAL"))
        return -1;
    *params = plan_json_field(j, selected, "parameters");
    return 1;
}
