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
#include <assert.h>
#include <junkie/tools/log.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/rex.h>

static char const *err_2_tempstr(struct rex *rex, int err)
{
	char *str = tempstr();
	(void)regerror(err, &rex->regex, str, TEMPSTR_SIZE);
	return str;
}

int rex_ctor(struct rex *rex, char const *regex, int cflags)
{
	rex->set = false;
    int err = regcomp(&rex->regex, regex, cflags);

    if (err) {
		SLOG(LOG_ERR, "Cannot compile regex '%s' : %s", regex, err_2_tempstr(rex, err));
        regfree(&rex->regex);
        return -1;
    }

	rex->set = true;
    return 0;
}

void rex_dtor(struct rex *rex)
{
	if (! rex->set) return;

	regfree(&rex->regex);
	rex->set = false;
}

bool rex_match(struct rex *rex, char const *str, size_t nb_matches, regmatch_t pmatch[], int eflags)
{
	if (! rex->set) return false;	// uncompiled RE never match.

    int err = regexec(&rex->regex, str, nb_matches, pmatch, eflags);
    if (err) {
        assert(err = REG_NOMATCH);
        return false;
    }

    SLOG(LOG_DEBUG, "found %zu matches", nb_matches);
    // TODO: check pmatch
    return true;
}

