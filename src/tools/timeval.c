// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <time.h>
#include <junkie/tools/timeval.h>
#include <junkie/tools/tempstr.h>

static char const Id[] = "$Id: ca2697009ffd184a7562c03c166f837e9c732021 $";

extern inline bool timeval_is_set(struct timeval const *);

extern inline void timeval_reset(struct timeval *);

static uint64_t timeval_2_usec(struct timeval const *tv)
{
    assert(timeval_is_set(tv));
    return (uint64_t)tv->tv_sec * 1000000 + tv->tv_usec;
}

static void usec_2_timeval(struct timeval *tv, uint64_t usec)
{
    tv->tv_sec  = usec / 1000000;
    tv->tv_usec = usec % 1000000;
}

// @returns micro-seconds
int64_t timeval_sub(struct timeval const *a, struct timeval const *b)
{
    int64_t a_ms = timeval_2_usec(a);
    int64_t b_ms = timeval_2_usec(b);

    return a_ms - b_ms;
}

int timeval_cmp(struct timeval const *a, struct timeval const *b)
{
    if (a->tv_sec < b->tv_sec) return -1;
    else if (a->tv_sec > b->tv_sec) return 1;
    else if (a->tv_usec < b->tv_usec) return -1;
    else if (a->tv_usec > b->tv_usec) return 1;
    return 0;
}

void timeval_add_usec(struct timeval *tv, int64_t usec)
{
    usec_2_timeval(tv, usec + timeval_2_usec(tv));
}

void timeval_add_sec(struct timeval *tv, int32_t sec)
{
    tv->tv_sec += sec;
}

char const *timeval_2_str(struct timeval const *tv)
{
    char *str = tempstr();
    int len = 0;
    if (tv->tv_sec) len += snprintf(str, TEMPSTR_SIZE, "%"PRIu32"s", (uint32_t)tv->tv_sec);
    if (tv->tv_usec) snprintf(str+len, TEMPSTR_SIZE-len, "%s%"PRIu32"us", len > 0 ? " ":"", (uint32_t)tv->tv_usec);
    return str;
}

void timeval_set_now(struct timeval *now)
{
#   ifdef HAVE_CLOCK_GETTIME
    // FIXME: configure should generate config.h with this HAVE_CLOCK_GETTIME
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    now->tv_sec = tp.tv_sec;
    now->tv_usec = tp.tv_nsec / 1000;
#   else
    gettimeofday(now, NULL);
#   endif
}
