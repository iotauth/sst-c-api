#ifndef PHYSICAL_PLAN_JSON_H
#define PHYSICAL_PLAN_JSON_H

#include <stddef.h>

/* Bounded JSON reader for Auth's verification plan, shared by every
 * CO_LOCATION method. The whole plan is tokenized once (at most
 * PLAN_JSON_MAX_TOKENS values, nesting depth 16); fields are then looked up
 * only in their owning object, never by substring search, and a duplicated
 * key is an error. */

#define PLAN_JSON_MAX_TOKENS 256

typedef struct {
    const char *start, *end; /* the value's text, quotes included */
    int next;                /* index of the token after this value */
    char type;               /* '{', '[', '"', 'n' (number), or t/f/n */
} plan_json_token;

typedef struct {
    const char* p;
    plan_json_token t[PLAN_JSON_MAX_TOKENS];
    int count;
} plan_json;

/* The value of `name` in object token `object`: its token index, -1 when
 * absent (or `object` is not an object), -2 when the key is duplicated. */
int plan_json_field(const plan_json* j, int object, const char* name);
/* 1 when token i is the string s (no escapes), else 0. */
int plan_json_is(const plan_json* j, int i, const char* s);
/* A JSON integer (optionally negative) within [min, max]; fractions and
 * exponents reject. @return 0 or -1. */
int plan_json_int(const plan_json* j, int i, long min, long max, long* out);
/* A positive JSON number that, times `scale`, is an integer up to 1,000,000
 * (e.g. a success fraction in millionths). @return 0 or -1. */
int plan_json_scaled(const plan_json* j, int i, unsigned scale, unsigned* out);
/* An entity name string without escapes, shorter than `capacity`.
 * @return 0 or -1. */
int plan_json_name(const plan_json* j, int i, char* out, size_t capacity);

/* Parses `plan` into `j` and finds the CO_LOCATION check:
 *   1: its selected method is `method` with MUTUAL topology; *params is
 *      that method's "parameters" object token;
 *   0: CO_LOCATION is absent and not required, or the method is DUMMY;
 *  -1: malformed plan, CO_LOCATION required but missing, another method,
 *      or a non-MUTUAL topology. */
int plan_co_location(const char* plan, const char* method, plan_json* j,
                     int* params);

#endif
