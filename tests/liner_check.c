// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <junkie/tools/miscmacs.h>
#include "proto/liner.c"

static unsigned nb_tokens(char const *buf, size_t buf_sz, struct liner_delimiter_set *delims)
{
    struct liner liner;
    liner_init(&liner, delims, buf, buf_sz);

    unsigned l;
    for (l = 0; !liner_eof(&liner); l++) {
        liner_next(&liner);
    }

    return l;
}

static void check_simple(void)
{
    static char const simple_text[] =
        "Maitre corbeau, sur un arbre perche,\n"
        "Tenait en son bec un fromage.\n"
        "\n";

    struct liner liner;
    struct liner_delimiter unix_eol[] = { { "\n", 1 } };
    struct liner_delimiter_set eols = { 1, unix_eol, false };

    liner_init(&liner, &eols, simple_text, sizeof(simple_text)-1);
    assert(liner_tok_length(&liner) == 36);
    assert(liner_parsed(&liner) == 37);

    liner_next(&liner);
    assert(liner_tok_length(&liner) == 29);

    liner_next(&liner);
    assert(liner_tok_length(&liner) == 0);
    assert(liner_parsed(&liner) == strlen(simple_text));

    assert(nb_tokens(simple_text, sizeof(simple_text)-1, &eols) == 3);
}

static void check_empty(void)
{
    static struct {
        char const *str;
        unsigned nb_lines[2];   // non greedy / greedy
    } line_tests[] = {
        { "", {0,0} }, { "blabla", {1,1} },
        { "\r\n", {1,1} }, { " \r\n", {1,1} } , { " \n", {1,1} },
        { "\r\n\r\n", {2,1} }, { "\n\n", {2,1} }, { "\r\n \n", {2,2} }, { "\n\r\r\n", {2,2} },
    };

    struct liner_delimiter eol[] = { { "\r\n", 2 }, { "\n", 1 } };
    struct liner_delimiter_set eols[2] = { { 2, eol, false }, { 2, eol, true } };

    for (unsigned e = 0; e < NB_ELEMS(line_tests); e++) {
        assert(nb_tokens(line_tests[e].str, strlen(line_tests[e].str), eols+0) == line_tests[e].nb_lines[0]);
        assert(nb_tokens(line_tests[e].str, strlen(line_tests[e].str), eols+1) == line_tests[e].nb_lines[1]);
    }
}

static void check_trunc_delim(void)
{
    static char const text[] = "blabla\r";

    struct liner liner;
    struct liner_delimiter eol[] = { { "\r\n", 2 } };
    struct liner_delimiter_set eols = { 1, eol, true };

    liner_init(&liner, &eols, text, sizeof(text)-1);
}

static void check_restart(void)
{
    static char const text[] = "xxAABxx";

    struct liner_delimiter ab[] = { { "AB", 2 } };
    struct liner_delimiter_set set = { 1, ab, false };

    assert(nb_tokens(text, strlen(text), &set) == 2);
}

static void check_longest_match(void)
{
    static char const text[] = "glopABCpasglop";

    struct liner liner;
    struct liner_delimiter abc[] = { { "ABC", 3 }, {"AB", 2 }, { "A", 1 } };
    struct liner_delimiter_set delims = { 3, abc, true };

    liner_init(&liner, &delims, text, sizeof(text)-1);
    assert(liner.start == text && liner.tok_size == 4);
    liner_next(&liner);
    assert(liner.start == text+7 && liner.tok_size == 7);
}

static void check_termination(void)
{
    static char const text[] = "glopABC_attention_voie_sans_issue";

    struct liner liner;
    struct liner_delimiter abc[] = { { "ABC", 3 }, {"AB", 2 }, { "A", 1 } };
    struct liner_delimiter_set delims = { 3, abc, true };

    liner_init(&liner, &delims, text, INT_MAX);
    assert(liner.start == text && liner.tok_size == 4);
}


int main(void)
{
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("liner_check.log");

    check_simple();
    check_empty();
    check_trunc_delim();
    check_longest_match();
    check_restart();
    check_termination();

    return EXIT_SUCCESS;
}
