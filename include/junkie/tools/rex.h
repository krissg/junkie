// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef REGEX_H_100414
#define REGEX_H_100414
#include <stdbool.h>
#include <sys/types.h>
#include <regex.h>

/** @file
 * @brief Thin wrapper around standard regex that handle errors.
 */

struct rex {
    regex_t regex;
	bool set;	// true if regex was successfully compiled
};

/** Same cflags than for regcomp :
 * REG_EXTENDED : Use POSIX Extended Regular Expression syntax when interpreting regex.  If not set, POSIX Basic Regular Expression syntax is used.
 * REG_ICASE    : Do not differentiate case.  Subsequent regexec() searches using this pattern buffer will be case insensitive.
 * REG_NOSUB    : Support for substring addressing of matches is not required.
 *                The nmatch and pmatch arguments to regexec() are ignored if the pattern buffer supplied was compiled with this flag set.
 * REG_NEWLINE  : Match-any-character operators don't match a newline.
 */
int rex_ctor(struct rex *, char const *, int cflags);

void rex_dtor(struct rex *);

/** Same eflags than for regexec :
 * REG_NOTBOL : The  match-beginning-of-line  operator  always fails to match (but see the compilation flag REG_NEWLINE above)
 *              This flag may be used when different portions of a string are passed to regexec() and the beginning of the string should not be interpreted as the beginning of the line.
 * REG_NOTEOL : The match-end-of-line operator always fails to match (but see the compilation flag REG_NEWLINE above).
 * @return true if the regex matched the string
 */
bool rex_match(struct rex *, char const *, size_t nb_matches, regmatch_t pmatch[], int eflags);

#endif
